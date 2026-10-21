//! AC-073: the SSA checker finds zero violations in the L1 form of every T1 and T2 function
//! and of 300 sampled T3 functions (WP-21).
//!
//! T3 is the test executable itself with its full symbol table (design Section 12.3). Its
//! functions build from a linear sweep over each symbol, so no full analysis runs.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ghidorah_analysis::code::{decode_at, flow_kind};
use ghidorah_analysis::fir::l1::{self, L1Ir};
use ghidorah_analysis::fir::{self, Input, Opts, Unit};
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, Limits};
use ghidorah_db::Program;
use ghidorah_ir::{Opc, Switches, check};
use ghidorah_json::Value;
use ghidorah_loader::{LoadOpts, SymKind, load};
use ghidorah_testkit::rng::{Xoshiro256ss, below};
use ghidorah_types::cc::SYSV_X86_64;

/// Gives the workspace root.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Loads `bytes` into a program at revision 0.
fn program_of(bytes: &[u8]) -> Program {
    let (binary, mem) = load(bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("the bytes load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("from_binary")
}

/// Gives the fixture paths of the tiers `T1`, `T2` and `PE` of the manifest. Design Section
/// 12.3 puts the PE32+ fixtures in T1.
fn fixture_paths() -> Vec<String> {
    let text = std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("manifest");
    let manifest = ghidorah_json::parse(&text, &ghidorah_json::Limits::DEFAULT).expect("JSON");
    manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .expect("fixtures list")
        .iter()
        .filter(|f| {
            matches!(
                f.get("tier").and_then(Value::as_str),
                Some("T1" | "T2" | "PE")
            )
        })
        .map(|f| {
            f.get("path")
                .and_then(Value::as_str)
                .expect("a path")
                .to_owned()
        })
        .collect()
}

/// Checks the L1 form of one function. Gives the violations as text.
fn violations(ir: &L1Ir) -> Vec<String> {
    check(&ir.ssa)
        .iter()
        .map(|v| format!("{:#x}: {v}", ir.l0.entry()))
        .collect()
}

/// Analyzes one fixture and checks each function. Gives the count and the failures.
fn check_fixture(path: &str) -> (usize, Vec<String>) {
    let bytes = std::fs::read(root().join(path)).expect("the fixture bytes");
    let mut p = program_of(&bytes);
    let out = Scheduler::new()
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete, "{path}: the run completes");
    let mut count = 0;
    let mut failures = Vec::new();
    for view in p.funcs() {
        let id = view.id();
        match l1::build(
            &p,
            id,
            &Opts::DEFAULT,
            &Switches::all(),
            &mut Fuel::new(50_000_000),
        ) {
            Ok(ir) => {
                count += 1;
                failures.extend(violations(&ir).into_iter().map(|v| format!("{path} {v}")));
            }
            Err(e) => failures.push(format!("{path} {:#x}: {e}", id.0.off)),
        }
    }
    (count, failures)
}

/// The functions of the T3 executable: the sized function symbols in executable memory.
fn t3_functions(p: &Program) -> Vec<(u64, u64)> {
    let mut out: BTreeSet<(u64, u64)> = BTreeSet::new();
    for s in &p.binary().symbols {
        if s.kind == SymKind::Func
            && s.size > 0
            && s.size < 0x1_0000
            && ghidorah_analysis::code::is_exec(p, s.addr)
        {
            out.insert((s.addr, s.size));
        }
    }
    out.into_iter().collect()
}

/// Gives the units of a linear sweep over the bytes of a T3 function. Gives `None` when an
/// instruction does not decode or has no flow kind: a decoder gap.
fn t3_units(p: &Program, entry: u64, size: u64) -> Option<BTreeMap<u64, Unit>> {
    let mut units = BTreeMap::new();
    let mut at = entry;
    let end = entry.checked_add(size)?;
    while at < end {
        let insn = decode_at(p, at)?;
        let flow = flow_kind(insn.flow())?;
        units.insert(
            at,
            Unit {
                len: insn.len(),
                flow,
                flags: 0,
            },
        );
        at = at.checked_add(u64::from(insn.len()))?;
    }
    Some(units)
}

/// Builds the L1 form of a T3 function from its units. An L0 build or an L1 lift error is a
/// failure.
fn t3_ir(p: &Program, entry: u64, units: BTreeMap<u64, Unit>) -> Result<L1Ir, String> {
    let no = |_: u64| false;
    let input = Input {
        entry,
        units,
        cases: BTreeMap::new(),
        noreturn: &no,
    };
    let mut fuel = Fuel::new(50_000_000);
    let l0 = fir::build_units(p, input, &Opts::DEFAULT, &mut fuel)
        .map_err(|e| format!("{entry:#x}: the L0 build fails: {e}"))?;
    l1::lift(l0, &SYSV_X86_64, &Switches::all(), &mut fuel)
        .map_err(|e| format!("{entry:#x}: the L1 lift fails: {e}"))
}

/// The result of a T3 check.
struct T3 {
    /// The functions with an L1 form that the checker ran on.
    checked: usize,
    /// The functions with a decoder gap.
    skipped: usize,
    /// The functions whose L0 build or L1 lift fails.
    build_failures: Vec<String>,
    /// The checker violations.
    violations: Vec<String>,
}

/// Checks `sample` decodable T3 functions with a fixed seed, or all T3 functions. The check
/// skips a function with a decoder gap. The sample draws functions until `sample` of them
/// decode.
fn check_t3(sample: Option<usize>) -> T3 {
    let exe = std::env::current_exe().expect("the test executable");
    let bytes = std::fs::read(exe).expect("the executable bytes");
    let p = program_of(&bytes);
    let mut all = t3_functions(&p);
    let mut rng = Xoshiro256ss::seed_from_u64(0x0073);
    let mut out = T3 {
        checked: 0,
        skipped: 0,
        build_failures: Vec::new(),
        violations: Vec::new(),
    };
    let mut decoded = 0;
    while !all.is_empty() && sample.is_none_or(|n| decoded < n) {
        let (entry, size) = if sample.is_some() {
            let len = u64::try_from(all.len()).expect("a count");
            let k = usize::try_from(below(&mut rng, len)).expect("an index");
            all.swap_remove(k)
        } else {
            all.remove(0)
        };
        let Some(units) = t3_units(&p, entry, size) else {
            out.skipped += 1;
            continue;
        };
        decoded += 1;
        match t3_ir(&p, entry, units) {
            Ok(ir) => {
                out.checked += 1;
                out.violations.extend(violations(&ir));
            }
            Err(e) => out.build_failures.push(e),
        }
    }
    out
}

#[test]
fn ac_073_ssa_invariants() {
    let paths = fixture_paths();
    let chunks: Vec<Vec<String>> = (0..4)
        .map(|k| paths.iter().skip(k).step_by(4).cloned().collect())
        .collect();
    let results: Vec<(usize, Vec<String>)> = std::thread::scope(|s| {
        #[expect(
            clippy::needless_collect,
            reason = "every thread starts before the first join"
        )]
        let handles: Vec<_> = chunks
            .iter()
            .map(|chunk| {
                s.spawn(move || {
                    let mut total = (0, Vec::new());
                    for path in chunk {
                        let (n, f) = check_fixture(path);
                        total.0 += n;
                        total.1.extend(f);
                    }
                    total
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a worker thread"))
            .collect()
    });
    let count: usize = results.iter().map(|r| r.0).sum();
    let failures: Vec<&String> = results.iter().flat_map(|r| &r.1).collect();
    assert!(count > 3_000, "only {count} T1 and T2 functions");
    assert!(
        failures.is_empty(),
        "{} failures:\n{:#?}",
        failures.len(),
        failures.iter().take(10).collect::<Vec<_>>()
    );
    let t3 = check_t3(Some(300));
    assert!(
        t3.build_failures.is_empty(),
        "T3 build failures:\n{:#?}",
        &t3.build_failures[..t3.build_failures.len().min(10)]
    );
    assert_eq!(
        t3.checked, 300,
        "the T3 sample, {} decoder gaps skipped",
        t3.skipped
    );
    assert!(
        t3.violations.is_empty(),
        "T3 violations:\n{:#?}",
        &t3.violations[..t3.violations.len().min(10)]
    );
}

#[test]
#[ignore = "tier2"]
fn ac_073_ssa_invariants_t3() {
    let t3 = check_t3(None);
    assert!(
        t3.checked > 1_000,
        "only {} T3 functions checked, {} skipped",
        t3.checked,
        t3.skipped
    );
    assert!(
        t3.skipped * 100 <= t3.checked,
        "{} T3 functions have a decoder gap",
        t3.skipped
    );
    assert!(
        t3.build_failures.is_empty(),
        "{} T3 build failures:\n{:#?}",
        t3.build_failures.len(),
        &t3.build_failures[..t3.build_failures.len().min(10)]
    );
    assert!(
        t3.violations.is_empty(),
        "T3 violations:\n{:#?}",
        &t3.violations[..t3.violations.len().min(10)]
    );
}

#[test]
fn l1_tail_jump_becomes_call() {
    let bytes = std::fs::read(root().join("fixtures/bin/hello.gcc-O2")).expect("the fixture");
    let mut p = program_of(&bytes);
    let _ = Scheduler::new()
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    let run = p.addrs_named("run").first().expect("run").off;
    let ir = l1::build(
        &p,
        FuncId(Address::ram(run)),
        &Opts::DEFAULT,
        &Switches::all(),
        &mut Fuel::unlimited(),
    )
    .expect("the L1 form");
    assert_eq!(ir.tail_calls.len(), 1, "run ends in a tail jump");
    let at = *ir.tail_calls.first().expect("one");
    let ops = ir.ssa.arena().insn_ops(at);
    assert!(
        ops.iter().any(|o| o.opc == Opc::Call),
        "the jump is a call in L1"
    );
    assert!(
        ir.l0.arena.insn_ops(at).iter().any(|o| o.opc == Opc::Jump),
        "the L0 IR keeps the jump"
    );
    let index = ir
        .ssa
        .op_index(
            ops.iter()
                .find(|o| o.opc == Opc::Call)
                .expect("the call")
                .id,
        )
        .expect("an index");
    assert!(
        ir.ssa
            .uses_at(index)
            .iter()
            .any(|(l, _)| *l == ghidorah_ir::Loc::RDI),
        "the tail call reads rdi"
    );
    assert!(violations(&ir).is_empty());
    let sets = l1::ssa_opts(&SYSV_X86_64);
    assert!(sets.ret_uses.contains(ghidorah_ir::Loc::RAX));
    assert!(!sets.call_defs.contains(ghidorah_ir::Loc::RBX));
    assert!(sets.call_defs.contains(ghidorah_ir::Loc::Flags));
    let err = l1::L1Error::Ssa(ghidorah_ir::SsaError::OutOfFuel);
    assert!(err.to_string().contains("fuel"));
}
