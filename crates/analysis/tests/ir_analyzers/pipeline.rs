//! The full analysis with the WP-19 analyzers: F1 gates, cold parts, published jump tables,
//! `main`, varargs flags, syscall notes, agent overrides and path independence.
//!
//! The tests with the ignore reason need the WP-19 analyzer rows of the registry. The register
//! step adds them. The path independence test also runs with the WP-15 rows only. Its agent
//! edits commit with the origin of their transaction, and its undos use the undo API.

use std::collections::BTreeSet;

use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, JumpTableId, TxId, WarningCode};
use ghidorah_db::undo::{self, UndoRequest};
use ghidorah_db::{
    CommentKind, Edit, FlowKind, FlowOverride, FuncView, History, JtMethod, JumpTable, Origin,
    PartKind, Program, Ref, RefKey, RefType, Scope, SessionLabel, Source, StartReason, TxLine,
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
    assert!(s.tp > 1_500, "T1 and T2 functions: {}", s.tp);
    assert!(s.per_mille() >= 980, "F1 {}: {:?}", s.per_mille(), s.misses);
}

#[test]
#[ignore = "needs the WP-19 analyzer rows of the register step"]
fn ac_078_f1_noeh() {
    let s = f1("noeh");
    assert!(s.tp > 600, "the noeh functions: {}", s.tp);
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
            // Without .eh_frame no FDE marks the part, so its range is a plain part.
            let func = p.func(fid(funcs[parent])).expect("the parent");
            let cold = func
                .func
                .parts
                .iter()
                .any(|x| x.kind == PartKind::Cold && x.range.contains(at));
            assert!(
                cold || f.variant == "noeh",
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

/// The session label of the agent edits of the tests.
fn session() -> SessionLabel {
    SessionLabel::new("test").expect("a label")
}

/// Gives the origin of the next agent transaction of `p`.
fn next_origin(p: &Program) -> Origin {
    let next = p.last_tx().0.checked_add(1).expect("a free transaction ID");
    Origin::new(Source::Agent, TxId(next), session(), false)
}

/// The result of one commit or one undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Done {
    /// The edits do not apply, or they change nothing.
    Refused,
    /// The commit applies. It holds the start band, or `None` when no edit affects analysis.
    Applied(Option<u16>),
}

/// Commits the edits that `make` gives for the origin of the new transaction. Records the
/// commit in `history`.
fn commit(p: &mut Program, history: &mut History, make: impl FnOnce(&Origin) -> Vec<Edit>) -> Done {
    let edits = make(&next_origin(p));
    let Ok(mut tx) = p.begin("test", Source::Agent, session()) else {
        return Done::Refused;
    };
    for edit in edits {
        if tx.apply(edit).is_err() {
            tx.abort();
            return Done::Refused;
        }
    }
    let Ok(commit) = tx.commit() else {
        return Done::Refused;
    };
    if commit.noop {
        return Done::Refused;
    }
    history.record(&TxLine::of_commit(&commit));
    Done::Applied(commit.start_band())
}

/// Undoes the last agent commit of the test session.
fn undo_last(p: &mut Program, history: &mut History) -> Done {
    let req = UndoRequest {
        scope: Scope::Session(session()),
        tx: None,
        count: 1,
        redo: false,
        force: false,
        dry_run: false,
        source: Source::Agent,
        session: session(),
    };
    let Ok(out) = undo::run(p, history, &req) else {
        return Done::Refused;
    };
    let Some(line) = out.line.as_ref() else {
        return Done::Refused;
    };
    history.record(line);
    Done::Applied(out.start_band)
}

/// One random agent edit before its origin.
#[derive(Debug, Clone, Copy)]
struct Pick {
    kind: u64,
    flag: bool,
    func: FuncId,
    unit: u64,
    flow: FlowKind,
    /// The source of an `AddRef`: the entry of a function with a start in the loaded file.
    /// The edits do not remove its code unit, so the reference does not become an orphan.
    source: u64,
}

/// Picks a random agent edit of an analysis-affecting kind.
fn random_pick(p: &Program, rng: &mut SplitMix64) -> Option<Pick> {
    let funcs: Vec<FuncId> = p.funcs().iter().map(FuncView::id).collect();
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
    let stable: Vec<u64> = p
        .funcs()
        .iter()
        .filter(|v| {
            matches!(
                v.func.start_reason,
                StartReason::Entry | StartReason::Symbol | StartReason::Fde
            )
        })
        .map(|v| v.id().0.off)
        .collect();
    let func = *funcs.get(pick(rng, funcs.len()))?;
    let (unit, flow) = *units.get(pick(rng, units.len()))?;
    let source = *stable.get(pick(rng, stable.len()))?;
    Some(Pick {
        kind: below(rng, 5),
        flag: below(rng, 2) == 0,
        func,
        unit,
        flow,
        source,
    })
}

/// Gives the edit of `pick` with the origin `o`.
fn edit_of(pick: Pick, o: &Origin) -> Edit {
    let Pick {
        kind,
        flag,
        func,
        unit,
        flow,
        source,
    } = pick;
    match kind {
        0 => Edit::SetNoreturn {
            id: func,
            noreturn: Some(o.fact(flag)),
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
                    from: Address::ram(source),
                    op_index: 0,
                    to: func.0,
                    kind: RefType::UnconditionalCall,
                },
                primary: true,
            }),
        },
    }
}

/// Runs random agent edits and undos on `path`, each with a re-analysis from its start band.
/// Then a new scheduler on a fresh load with the live edits must give the same analysis set.
fn path_independent(path: &str, seed: u64, steps: usize) {
    let mut p = program(path);
    let mut sched = analyze(&mut p);
    let mut history = History::new();
    let mut rng = SplitMix64::new(seed);
    let mut live: Vec<Pick> = Vec::new();
    let mut restarts = 0u32;
    for _ in 0..steps {
        let undo = !live.is_empty() && below(&mut rng, 3) == 0;
        let done = if undo {
            let band = undo_last(&mut p, &mut history);
            if band != Done::Refused {
                live.pop();
            }
            band
        } else {
            let Some(pick) = random_pick(&p, &mut rng) else {
                continue;
            };
            let band = commit(&mut p, &mut history, |o| vec![edit_of(pick, o)]);
            if band != Done::Refused {
                live.push(pick);
            }
            band
        };
        if let Done::Applied(Some(band)) = done {
            restarts += 1;
            sched.restart(band);
            let out = sched
                .run(&mut p, Until::Full, &mut Fuel::unlimited())
                .expect("a re-analysis");
            assert_eq!(out.state, RunState::Complete);
        }
    }
    assert!(
        restarts > 0,
        "{path} seed {seed}: an edit restarts the analysis"
    );
    // The code checks of the edits need the code units: the fresh load gets one analysis
    // before the edits. The last run starts from nothing.
    let mut fresh = program(path);
    let _ = analyze(&mut fresh);
    let mut fresh_history = History::new();
    for pick in live {
        assert!(
            commit(&mut fresh, &mut fresh_history, |o| vec![edit_of(pick, o)]) != Done::Refused,
            "the live edits apply"
        );
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
    let f = ghidorah_db::Function::new(
        Address::ram(BASE + 0x20),
        StartReason::Agent,
        100,
        Source::Agent,
    );
    let mut history = History::new();
    let band = commit(&mut p, &mut history, |o| {
        vec![
            Edit::CreateFunction(Box::new(ghidorah_db::FuncRecord {
                func: f,
                vars: Vec::new(),
                plate: None,
            })),
            Edit::SetNoreturn {
                id: fid(BASE + 0x10),
                noreturn: Some(o.fact(true)),
            },
        ]
    });
    let Done::Applied(band) = band else {
        panic!("the edits commit");
    };
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
