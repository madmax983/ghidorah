//! Orphaned agent facts after a re-analysis (design Section 3.9, AC-126).
//!
//! The blob has a call at `0x0` to `0x10`, a `ret` at `0x5` and an unreached function at
//! `0x20`. Agent edits give each fact an anchor, and later edits take the anchors away.

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]
#![allow(clippy::panic, reason = "a test fails through a panic")]

use ghidorah_analysis::orphans::{OrphanKind, find};
use ghidorah_analysis::{RunState, Scheduler, Until};
use ghidorah_base::{Address, Fuel, FuncId, Id, Limits, VarId};
use ghidorah_db::{
    Edit, FactKey, FlowOverride, Origin, Program, Ref, RefKey, RefType, SessionLabel, Source,
    SymKind, VarField,
};
use ghidorah_loader::{LoadOpts, load};
use ghidorah_types::Prim;

/// The load address of the blob.
const BASE: u64 = 0x40_0000;

/// Gives the blob: `call 0x10; ret`, `ret` at `0x10`, `mov eax, 1; ret` at `0x20`.
fn blob() -> Vec<u8> {
    let mut bytes = vec![0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3];
    bytes.resize(0x10, 0xcc);
    bytes.push(0xc3);
    bytes.resize(0x20, 0xcc);
    bytes.extend([0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
    bytes.resize(0x40, 0xcc);
    bytes
}

/// Loads the blob and runs the first analysis. Gives the program and its scheduler.
fn analyzed() -> (Program, Scheduler) {
    let opts = LoadOpts::raw(BASE, Some(BASE));
    let (binary, mem) = load(&blob(), &opts, &Limits::DEFAULT).expect("the blob loads");
    let mut p = Program::from_binary(binary, mem, &Limits::DEFAULT).expect("a program");
    let mut sched = Scheduler::new();
    let out = sched
        .run(&mut p, Until::Full, &mut Fuel::unlimited())
        .expect("the analysis runs");
    assert_eq!(out.state, RunState::Complete);
    (p, sched)
}

/// Commits the agent edits of `make`. Then runs the re-analysis from the start band.
fn edit(p: &mut Program, sched: &mut Scheduler, make: impl FnOnce(&Origin) -> Vec<Edit>) {
    let session = SessionLabel::new("test").expect("a label");
    let mut tx = p
        .begin("func_edit", Source::Agent, session)
        .expect("a transaction");
    let origin = tx.origin().clone();
    for e in make(&origin) {
        tx.apply(e).expect("the edit applies");
    }
    let commit = tx.commit().expect("the commit");
    if let Some(band) = commit.start_band() {
        sched.restart(band);
        let out = sched
            .run(p, Until::Full, &mut Fuel::unlimited())
            .expect("the re-analysis runs");
        assert_eq!(out.state, RunState::Complete);
    }
}

/// Gives the RAM address of the blob offset `off`.
const fn at(off: u64) -> Address {
    Address::ram(BASE + off)
}

/// Gives a reference key.
const fn key(from: u64, to: u64, kind: RefType) -> RefKey {
    RefKey {
        from: at(from),
        op_index: 0,
        to: at(to),
        kind,
    }
}

/// Gives the variable `var:<0x20>/param:0`.
fn var() -> VarId {
    match Id::parse(&format!("var:{:#x}/param:0", BASE + 0x20)) {
        Ok(Id::Var(v)) => v,
        other => panic!("a variable ID: {other:?}"),
    }
}

#[test]
fn ac_126_orphans_of_a_lost_function() {
    let (mut p, mut sched) = analyzed();
    let seed = key(0x0, 0x20, RefType::UnconditionalCall);
    let int = p.types().store().prim(Prim::Int);
    edit(&mut p, &mut sched, |o| {
        vec![Edit::AddRef {
            fact: o.fact(Ref {
                key: seed,
                primary: false,
            }),
        }]
    });
    assert!(p.analysis().funcs().get(FuncId(at(0x20))).is_some());
    edit(&mut p, &mut sched, |o| {
        vec![
            Edit::SetVarFact {
                var: var(),
                field: VarField::Type(Some(o.fact(int))),
            },
            Edit::SetName {
                addr: at(0x20),
                key: None,
                kind: SymKind::Function,
                primary: true,
                name: Some(o.fact("set_one".to_owned())),
                evidence: Vec::new(),
            },
        ]
    });
    assert!(find(&p).is_empty(), "every fact has its anchor");
    edit(&mut p, &mut sched, |_| vec![Edit::RemoveRef { key: seed }]);
    assert!(p.analysis().funcs().get(FuncId(at(0x20))).is_none());
    let found = find(&p);
    let kinds: Vec<OrphanKind> = found.iter().map(|o| o.kind).collect();
    assert_eq!(kinds, [OrphanKind::Name, OrphanKind::Var], "{found:?}");
    let var_orphan = found.get(1).expect("the variable");
    assert_eq!(var_orphan.key, FactKey::Var(var()));
    assert_eq!(var_orphan.id(), var().to_string());
    assert!(var_orphan.lost_function());
    let name = found.first().expect("the name");
    assert_eq!(name.at, at(0x20));
    assert_eq!(name.id(), at(0x20).to_string());
    assert_eq!(name.source, Source::Agent);
    assert!(p.var(&var()).ty.is_some(), "the variable fact stays");
    assert_eq!(
        p.name(at(0x20)).map(|n| n.text),
        Some("set_one".to_owned()),
        "the name stays as a label"
    );
}

#[test]
fn an_agent_function_with_no_analysis_record_is_an_orphan() {
    let (mut p, _) = analyzed();
    let session = SessionLabel::new("test").expect("a label");
    let mut tx = p
        .begin("func_edit", Source::Agent, session)
        .expect("a transaction");
    let f = ghidorah_db::Function::new(
        at(0x20),
        ghidorah_db::StartReason::Agent,
        100,
        Source::Agent,
    );
    tx.apply(Edit::CreateFunction(Box::new(ghidorah_db::FuncRecord {
        func: f,
        vars: Vec::new(),
        plate: None,
    })))
    .expect("the create applies");
    tx.commit().expect("the commit");
    // No re-analysis runs, so the analysis layer has no record at the entry.
    let found = find(&p);
    assert_eq!(found.len(), 1, "{found:?}");
    let orphan = found.first().expect("the function");
    assert_eq!(orphan.kind, OrphanKind::Function);
    assert_eq!(orphan.id(), FuncId(at(0x20)).to_string());
    assert!(orphan.lost_function());
}

#[test]
fn ac_126_orphan_reference_of_lost_code() {
    let (mut p, mut sched) = analyzed();
    let read = key(0x5, 0x30, RefType::Read);
    edit(&mut p, &mut sched, |o| {
        vec![Edit::AddRef {
            fact: o.fact(Ref {
                key: read,
                primary: false,
            }),
        }]
    });
    assert!(find(&p).is_empty());
    // The call becomes a jump, so the `ret` at 0x5 is no longer code.
    edit(&mut p, &mut sched, |o| {
        vec![Edit::SetFlowOverride {
            at: at(0x0),
            flow: Some(o.fact(FlowOverride::CallAsJump)),
        }]
    });
    assert!(p.code_unit(BASE + 0x5).is_none(), "the source is not code");
    let found = find(&p);
    assert_eq!(found.len(), 1, "{found:?}");
    let orphan = found.first().expect("the reference");
    assert_eq!(orphan.kind, OrphanKind::Ref);
    assert_eq!(orphan.key, FactKey::Ref(read));
    assert_eq!(orphan.at, at(0x5));
    assert!(orphan.id().starts_with("ref:"), "{}", orphan.id());
    assert!(!orphan.lost_function());
    assert!(p.base().refs().get(&read).is_some(), "the reference stays");
    assert!(p.check_invariants().is_empty());
    assert_eq!(OrphanKind::Ref.to_string(), "reference");
    assert_eq!(OrphanKind::Function.name(), "function");
}
