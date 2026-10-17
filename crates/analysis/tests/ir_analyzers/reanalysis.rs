//! Re-analysis after agent edits: path independence (AC-097), fuel slicing (AC-092) and the
//! seeds and conflicts of agent overrides.
//!
//! The agent edits commit with the origin of their transaction, and the undos use the undo API.
//! The path independence test also runs with the WP-15 rows only. The override test needs the
//! WP-19 analyzer rows of the registry. The register step adds them.

use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, JumpTableId, TxId, WarningCode};
use ghidorah_db::undo::{self, UndoRequest};
use ghidorah_db::{
    Edit, FlowKind, FlowOverride, FuncView, History, JtMethod, JumpTable, Origin, Program, Ref,
    RefKey, RefType, Scope, SessionLabel, Source, StartReason, TxLine,
};
use ghidorah_testkit::rng::{SplitMix64, below};

use crate::blob::{BASE, load};
use crate::support::{analyze, analyzed, fid, program};

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
