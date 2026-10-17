//! The full analysis with the WP-19 analyzers: F1 gates, cold parts, published jump tables,
//! `main`, varargs flags, syscall notes, agent overrides and path independence.
//!
//! Each test needs the WP-19 analyzer rows of the registry. The register step adds them.

use std::collections::BTreeSet;

use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, JumpTableId, WarningCode};
use ghidorah_db::{
    Applied, CommentKind, Edit, FlowKind, FlowOverride, JtMethod, JumpTable, PartKind, Program,
    Ref, RefKey, RefType, SessionLabel, Source, StartReason,
};
use ghidorah_json::Value;
use ghidorah_testkit::rng::{SplitMix64, below};

use crate::blob::{BASE, load};
use crate::support::{
    analyze, analyzed, cached, fid, fixtures, hex, list, program, truth, truth_funcs,
};

/// The function-start counts of a set of fixtures: true positives, false positives and false
/// negatives, with the misses of each fixture.
#[derive(Debug, Default)]
struct F1 {
    tp: u64,
    fp: u64,
    fneg: u64,
    misses: Vec<String>,
}

impl F1 {
    /// Gives the F1 score in thousandths.
    fn per_mille(&self) -> u64 {
        2_000 * self.tp / (2 * self.tp + self.fp + self.fneg).max(1)
    }
}

/// Counts the function starts of the fixtures of `variant` against their truth.
fn f1(variant: &str) -> F1 {
    let mut out = F1::default();
    for f in fixtures() {
        if f.variant != variant {
            continue;
        }
        let t = truth(&f.truth);
        let want: BTreeSet<u64> = truth_funcs(&t).values().copied().collect();
        let p = cached(&f.path);
        let found: BTreeSet<u64> = p
            .funcs()
            .iter()
            .filter(|v| !v.func.flags.thunk)
            .map(|v| v.id().0.off)
            .collect();
        let fp: Vec<u64> = found.difference(&want).copied().collect();
        let fneg: Vec<u64> = want.difference(&found).copied().collect();
        out.tp += u64::try_from(want.intersection(&found).count()).expect("a count");
        out.fp += u64::try_from(fp.len()).expect("a count");
        out.fneg += u64::try_from(fneg.len()).expect("a count");
        if !fp.is_empty() || !fneg.is_empty() {
            out.misses
                .push(format!("{}: fp {fp:x?} fn {fneg:x?}", f.path));
        }
    }
    out
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_077_f1_eh() {
    let s = f1("stripped");
    assert!(s.tp > 2_000, "T1 and T2 functions: {}", s.tp);
    assert!(s.per_mille() >= 980, "F1 {}: {:?}", s.per_mille(), s.misses);
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_078_f1_noeh() {
    let s = f1("noeh");
    assert!(s.tp > 1_000, "the noeh functions: {}", s.tp);
    assert!(s.per_mille() >= 900, "F1 {}: {:?}", s.per_mille(), s.misses);
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_079_cold_parts() {
    let mut checked = 0;
    for f in fixtures() {
        let t = truth(&f.truth);
        let parts = list(&t, "cold_parts");
        if parts.is_empty() {
            continue;
        }
        let funcs = truth_funcs(&t);
        let p = cached(&f.path);
        for part in parts {
            let at = hex(part.get("addr").expect("an address"));
            let parent = part
                .get("parent")
                .and_then(Value::as_str)
                .expect("a parent");
            let owner = p.owner_of(Address::ram(at));
            assert_eq!(owner, Some(fid(funcs[parent])), "{}: {parent}.cold", f.path);
            let func = p.func(fid(funcs[parent])).expect("the parent");
            assert!(
                func.func
                    .parts
                    .iter()
                    .any(|x| x.kind == PartKind::Cold && x.range.contains(at)),
                "{}: {parent}.cold is a cold part",
                f.path
            );
            assert!(
                p.func(fid(at)).is_none(),
                "{}: no function at the part",
                f.path
            );
            checked += 1;
        }
    }
    assert!(checked >= 70, "the fixtures have cold parts: {checked}");
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_081_jumptable_truth() {
    let (mut total, mut right) = (0, 0);
    let mut wrong = Vec::new();
    for f in fixtures() {
        if !matches!(f.variant.as_str(), "none" | "stripped") {
            continue;
        }
        let t = truth(&f.truth);
        let tables = list(&t, "jump_tables");
        if tables.is_empty() {
            continue;
        }
        let funcs = truth_funcs(&t);
        let p = cached(&f.path);
        for table in tables {
            total += 1;
            let name = table.get("func").and_then(Value::as_str).expect("a name");
            let base = hex(table.get("table").expect("a base"));
            let want: Vec<Address> = list(table, "targets")
                .iter()
                .map(|v| Address::ram(hex(v)))
                .collect();
            let owner = fid(funcs[name]);
            let found = p.analysis().jumptables().iter().find(|(id, j)| {
                j.value.base == Some(Address::ram(base)) && p.owner_of(id.0) == Some(owner)
            });
            match found {
                Some((_, j)) if j.value.targets == want && j.value.resolved => right += 1,
                Some((id, j)) => wrong.push(format!("{}: {}: {:?}", f.path, id.0, j.value)),
                None => {}
            }
        }
    }
    assert!(
        total > 400,
        "the tables of the builds and their twins: {total}"
    );
    assert!(wrong.is_empty(), "wrong targets: {wrong:?}");
    assert!(
        right * 100 >= total * 95,
        "{right} of {total} tables resolve"
    );
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_082a_unresolved_remedy() {
    // mov rax, [rdi]; jmp rax: no guard bounds the index.
    let p = {
        let mut p = load(&[0x48, 0x8b, 0x07, 0xff, 0xe0], 0);
        let _ = analyze(&mut p);
        p
    };
    let site = Address::ram(BASE + 3);
    let table = p.jump_table(JumpTableId(site)).expect("a record");
    assert!(!table.value.resolved);
    assert!(table.value.targets.is_empty());
    assert_eq!(table.value.method, JtMethod::A);
    let func = p.func(fid(BASE)).expect("the function");
    let caveat = func
        .func
        .caveats
        .iter()
        .find(|c| c.code == WarningCode::JumptableUnresolved)
        .expect("W_JUMPTABLE_UNRESOLVED");
    assert_eq!(caveat.at, Some(site));
    assert!(
        caveat
            .remedy
            .as_deref()
            .is_some_and(|r| r.contains("func_edit") && r.contains("set_jumptable"))
    );
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_084_no_merged_functions() {
    let mut checked = 0;
    for f in fixtures() {
        let t = truth(&f.truth);
        let starts: BTreeSet<u64> = truth_funcs(&t).values().copied().collect();
        let p = cached(&f.path);
        for view in p.funcs() {
            let entry = view.id().0.off;
            for r in view.func.body.ranges() {
                for s in starts.range(r.first..=r.last) {
                    assert_eq!(*s, entry, "{}: {} holds {s:#x}", f.path, view.id());
                }
            }
            checked += 1;
        }
    }
    assert!(checked > 2_000, "{checked}");
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_088_main_discovery() {
    let mut found = 0;
    for f in fixtures() {
        if f.variant != "stripped" {
            continue;
        }
        let t = truth(&f.truth);
        let Some(&main) = truth_funcs(&t).get("main") else {
            continue;
        };
        let p = cached(&f.path);
        let func = p
            .func(fid(main))
            .unwrap_or_else(|| panic!("{}: main", f.path));
        assert_eq!(func.func.start_reason, StartReason::Main, "{}", f.path);
        assert_eq!(func.func.confidence, 95);
        let name = p.name(Address::ram(main)).expect("a name");
        assert_eq!(name.text, "main", "{}", f.path);
        assert_eq!(name.source, Source::Analysis);
        found += 1;
    }
    assert!(found >= 50, "the stripped fixtures with main: {found}");
    // An unstripped file keeps its imported name.
    let p = cached("fixtures/bin/hello.gcc-O2");
    let main = crate::support::named(p, "main");
    assert_eq!(
        p.name(Address::ram(main)).map(|n| n.source),
        Some(Source::Imported)
    );
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_090b_varargs() {
    let mut checked = 0;
    for f in fixtures() {
        if f.program != "varargs" {
            continue;
        }
        let t = truth(&f.truth);
        let funcs = truth_funcs(&t);
        let p = cached(&f.path);
        let protos = t
            .get("facts")
            .and_then(|x| x.get("prototypes"))
            .and_then(Value::as_array)
            .expect("prototypes");
        for proto in protos {
            let name = proto.get("name").and_then(Value::as_str).expect("a name");
            let varargs = proto.get("varargs").and_then(Value::as_bool);
            let func = p.func(fid(funcs[name])).expect("the function");
            assert_eq!(Some(func.func.flags.varargs), varargs, "{} {name}", f.path);
            checked += 1;
        }
    }
    assert!(checked >= 60, "{checked}");
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn syscall_notes() {
    for f in fixtures() {
        if f.program != "syscall_only" {
            continue;
        }
        let t = truth(&f.truth);
        let p = cached(&f.path);
        for s in list(&t, "syscalls") {
            let site = Address::ram(hex(s.get("site").expect("a site")));
            let name = s.get("name").and_then(Value::as_str).expect("a name");
            let note = p.comment(site, CommentKind::Eol).expect("a note");
            assert_eq!(note.value, format!("sys:{name}"), "{}", f.path);
            assert_eq!(note.source, Source::Analysis);
        }
    }
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn tail_calls_and_cold_parts_of_one_file() {
    let p = cached("fixtures/bin/cold_split.gcc-O2.stripped");
    let t = truth("fixtures/truth/cold_split.gcc-O2.json");
    let funcs = truth_funcs(&t);
    let tm = funcs["register_tm_clones"];
    let func = p.func(fid(tm)).expect("the tail-call target is a function");
    assert_eq!(func.func.start_reason, StartReason::TailCall);
    assert_eq!(func.func.confidence, 80);
    let digit = p.func(fid(funcs["parse_digit"])).expect("parse_digit");
    assert!(
        digit.func.body.contains(0x10c4),
        "the cold part is in the body"
    );
}

/// Commits `edits` as the agent. Gives the inverses in undo order and the start band.
fn commit(p: &mut Program, edits: Vec<Edit>) -> Option<(Vec<Edit>, Option<u16>)> {
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = p.begin("test", Source::Agent, label).ok()?;
    for edit in edits {
        if tx.apply(edit).is_err() {
            tx.abort();
            return None;
        }
    }
    let commit = tx.commit().ok()?;
    let inverses: Vec<Edit> = commit
        .edits
        .iter()
        .rev()
        .map(|a: &Applied| a.inverse.clone())
        .collect();
    let band = commit.start_band();
    Some((inverses, band))
}

/// Gives a random agent edit of an analysis-affecting kind.
fn random_edit(p: &Program, rng: &mut SplitMix64) -> Option<Edit> {
    let funcs: Vec<FuncId> = p.funcs().iter().map(|v| v.id()).collect();
    let units: Vec<(u64, FlowKind)> = p
        .analysis()
        .listing()
        .units_in(ghidorah_base::Range {
            first: 0,
            last: u64::MAX,
        })
        .map(|(at, u)| {
            let ghidorah_db::CodeUnit::Insn { flow, .. } = u;
            (at, *flow)
        })
        .collect();
    let pick = |rng: &mut SplitMix64, n: usize| -> usize {
        usize::try_from(below(rng, u64::try_from(n.max(1)).expect("small"))).expect("small")
    };
    let func = *funcs.get(pick(rng, funcs.len()))?;
    let (unit, flow) = *units.get(pick(rng, units.len()))?;
    let o = ghidorah_db::Origin::new(
        Source::Agent,
        ghidorah_base::TxId(0),
        SessionLabel::new("test").expect("a label"),
        false,
    );
    Some(match below(rng, 5) {
        0 => Edit::SetNoreturn {
            id: func,
            noreturn: Some(o.fact(below(rng, 2) == 0)),
        },
        1 => {
            let f = ghidorah_db::Function::new(
                Address::ram(unit),
                StartReason::Agent,
                100,
                Source::Agent,
            );
            Edit::CreateFunction(Box::new(ghidorah_db::FuncRecord {
                func: f,
                vars: Vec::new(),
                plate: None,
            }))
        }
        2 if flow == FlowKind::IJmp => Edit::SetJumpTable {
            id: JumpTableId(Address::ram(unit)),
            table: Some(o.fact(JumpTable {
                base: None,
                entry_size: 0,
                count: 1,
                targets: vec![func.0],
                method: JtMethod::Agent,
                resolved: true,
            })),
        },
        2 | 3 if matches!(flow, FlowKind::Call | FlowKind::ICall) => Edit::SetFlowOverride {
            at: Address::ram(unit),
            flow: Some(o.fact(if flow == FlowKind::Call {
                FlowOverride::CallAsJump
            } else {
                FlowOverride::IndirectTargets(vec![func.0])
            })),
        },
        _ => Edit::AddRef {
            fact: o.fact(Ref {
                key: RefKey {
                    from: Address::ram(unit),
                    op_index: 0,
                    to: func.0,
                    kind: RefType::UnconditionalCall,
                },
                primary: true,
            }),
        },
    })
}

/// Runs random agent edits and undos on `path`, each with a re-analysis from its start band.
/// Then a fresh load with the live edits must give the same analysis set.
fn path_independent(path: &str, seed: u64, steps: usize) {
    let mut p = program(path);
    let mut sched = analyze(&mut p);
    let mut rng = SplitMix64::new(seed);
    let mut live: Vec<(Vec<Edit>, Vec<Edit>)> = Vec::new();
    for _ in 0..steps {
        let undo = !live.is_empty() && below(&mut rng, 3) == 0;
        let done = if undo {
            let (_, inverses) = live.pop().expect("an applied commit");
            commit(&mut p, inverses).map(|(_, band)| band)
        } else {
            let Some(edit) = random_edit(&p, &mut rng) else {
                continue;
            };
            commit(&mut p, vec![edit.clone()]).map(|(inverses, band)| {
                live.push((vec![edit], inverses));
                band
            })
        };
        if let Some(Some(band)) = done {
            sched.restart(band);
            let out = sched
                .run(&mut p, Until::Full, &mut Fuel::unlimited())
                .expect("a re-analysis");
            assert_eq!(out.state, RunState::Complete);
        }
    }
    let mut fresh = program(path);
    let edits: Vec<Edit> = live.into_iter().flat_map(|(e, _)| e).collect();
    if !edits.is_empty() {
        assert!(commit(&mut fresh, edits).is_some(), "the live edits apply");
    }
    let mut sched = Scheduler::new();
    let out = sched
        .run(&mut fresh, Until::Full, &mut Fuel::unlimited())
        .expect("a fresh run");
    assert_eq!(out.state, RunState::Complete);
    assert!(
        p.analysis() == fresh.analysis(),
        "{path} seed {seed}: the re-analysis equals a fresh load"
    );
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_097_reanalysis_path_independent() {
    for path in [
        "fixtures/bin/switch.gcc-O2.stripped",
        "fixtures/bin/cold_split.gcc-O2.stripped",
        "fixtures/bin/noreturn_wrappers.clang-O2.stripped",
        "fixtures/bin/func_ptrs.gcc-O2",
    ] {
        for seed in 0..3 {
            path_independent(path, seed, 6);
        }
    }
}

#[test]
#[ignore = "tier2"]
fn ac_097_t2() {
    for path in [
        "fixtures/bin/large.gcc-O2.stripped",
        "fixtures/bin/large.clang-O2.noeh",
    ] {
        path_independent(path, 7, 8);
    }
}

#[test]
#[ignore = "tier2"]
fn ac_092_fuel_slicing_t2() {
    for path in [
        "fixtures/bin/large.gcc-O2.stripped",
        "fixtures/bin/large.clang-O2.stripped",
    ] {
        let full = analyzed(path);
        let want = full.state_hash().expect("a hash");
        let mut rng = SplitMix64::new(92);
        for _ in 0..2 {
            let k = 1 + below(&mut rng, 20_000);
            let mut p = program(path);
            let mut sched = Scheduler::new();
            let mut slices = 0u64;
            loop {
                slices += 1;
                assert!(slices < 10_000_000, "the slices make progress");
                let out = sched
                    .run(&mut p, Until::Full, &mut Fuel::new(k))
                    .expect("a slice");
                if out.state == RunState::Complete {
                    break;
                }
            }
            assert_eq!(p.state_hash().expect("a hash"), want, "{path} k {k}");
        }
    }
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn agent_overrides_seed_and_conflict() {
    // 0x0: call 0x10; ret.  0x10: ret.  0x20: ret, reached by no flow.
    let mut bytes = vec![0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3];
    bytes = crate::blob::pad(bytes, 0x10);
    bytes.push(0xc3);
    bytes = crate::blob::pad(bytes, 0x20);
    bytes.push(0xc3);
    let mut p = load(&bytes, 0);
    let _ = analyze(&mut p);
    assert!(p.func(fid(BASE + 0x20)).is_none());
    let o = ghidorah_db::Origin::new(
        Source::Agent,
        ghidorah_base::TxId(0),
        SessionLabel::new("test").expect("a label"),
        false,
    );
    let f = ghidorah_db::Function::new(
        Address::ram(BASE + 0x20),
        StartReason::Agent,
        100,
        Source::Agent,
    );
    let edits = vec![
        Edit::CreateFunction(Box::new(ghidorah_db::FuncRecord {
            func: f,
            vars: Vec::new(),
            plate: None,
        })),
        Edit::SetNoreturn {
            id: fid(BASE + 0x10),
            noreturn: Some(o.fact(true)),
        },
    ];
    let (_, band) = commit(&mut p, edits).expect("the edits commit");
    let mut sched = Scheduler::shadow();
    sched.restart(band.expect("an analysis edit"));
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("a re-analysis");
    assert_eq!(out.state, RunState::Complete);
    let seeded = p.func(fid(BASE + 0x20)).expect("the agent function");
    assert!(seeded.func.body.contains(BASE + 0x20));
    assert!(
        p.code_unit(BASE + 0x20).is_some(),
        "Disasm decodes the agent function"
    );
    let callee = p.func(fid(BASE + 0x10)).expect("the callee");
    let conflict = callee
        .func
        .caveats
        .iter()
        .find(|c| c.code == WarningCode::AgentOverrideConflict)
        .expect("W_AGENT_OVERRIDE_CONFLICT");
    assert!(
        conflict
            .remedy
            .as_deref()
            .is_some_and(|r| r.contains("noreturn: false")),
        "the remedy holds the analysis value"
    );
    assert_eq!(
        callee.noreturn.map(|n| (n.value, n.source)),
        Some((true, Source::Agent)),
        "the agent flag stays"
    );
}
