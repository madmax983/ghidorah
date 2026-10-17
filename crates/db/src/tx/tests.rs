use std::panic::{AssertUnwindSafe, catch_unwind};

use ghidorah_base::{ErrorCode, FuncId, JumpTableId, NoteId, Range, Rev, Storage, TxId, VarId};
use ghidorah_json::Value;
use ghidorah_kernel::RangeSet;
use ghidorah_types::Prim;

use super::{Tx, TxError, TxLabel};
use crate::comments::CommentKind;
use crate::edit::{Edit, EditError, FuncRecord, VarField};
use crate::epochs::Table;
use crate::fact::SessionLabel;
use crate::funcs::{Function, Part, PartKind, StartReason};
use crate::jumptables::{JtMethod, JumpTable};
use crate::listing::DataDef;
use crate::notes::{Note, NoteKind, NoteStatus};
use crate::overrides::FlowOverride;
use crate::program::Program;
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::symbols::SymKind;
use crate::tests::{analysis_set, func_type, ram, seeded, session};
use crate::vars::VarFact;

fn agent(p: &mut Program) -> Tx<'_> {
    p.begin("test", Source::Agent, session("mcp-1")).unwrap()
}

fn rename(tx: &Tx<'_>, at: u64, name: &str) -> Edit {
    Edit::SetName {
        addr: ram(at),
        key: None,
        kind: SymKind::Function,
        primary: true,
        name: Some(tx.fact(name.to_string())),
        evidence: Vec::new(),
    }
}

fn hash(p: &Program) -> crate::hash::StateHash {
    p.state_hash().unwrap()
}

fn base_func(tx: &Tx<'_>, entry: u64, last: u64) -> Function {
    let mut f = Function::new(ram(entry), StartReason::Agent, 100, tx.origin().source);
    f.body = RangeSet::from_ranges(&[Range { first: entry, last }]);
    f
}

fn note(tx: &Tx<'_>, id: u64, text: &str) -> Note {
    Note {
        id: NoteId(id),
        kind: NoteKind::Todo,
        text: text.to_string(),
        at: Some(ram(0x1080)),
        func: None,
        status: NoteStatus::Open,
        tags: Vec::new(),
        evidence: vec!["fn:0x1080".to_string()],
        claims: Vec::new(),
        set: None,
        src: tx.origin().source,
        session: tx.origin().session.clone(),
        rev: tx.pending_rev(),
    }
}

#[test]
fn labels_and_sources_obey_their_rules() {
    assert_eq!(
        TxLabel::new("symbol_rename+comment_set").unwrap().as_str(),
        "symbol_rename+comment_set"
    );
    for bad in ["", "two words", "naïve", &"x".repeat(129)] {
        assert_eq!(TxLabel::new(bad), Err(TxError::BadLabel), "{bad:?}");
    }
    assert!(TxLabel::new(&"x".repeat(128)).is_ok());
    let mut p = seeded();
    assert_eq!(
        p.begin("x", Source::Default, session("cli")).err(),
        Some(TxError::DefaultSource)
    );
    assert_eq!(
        p.begin("a b", Source::Agent, session("cli")).err(),
        Some(TxError::BadLabel)
    );
    assert_eq!(TxError::Poisoned.code(), ErrorCode::Conflict);
    assert_eq!(TxError::Exhausted.code(), ErrorCode::LimitExceeded);
    assert!(TxError::BadLabel.to_string().contains("128"));
}

#[test]
fn commit_takes_the_next_rev_and_tx() {
    let mut p = seeded();
    let mut tx = agent(&mut p);
    assert_eq!(tx.id(), TxId(1));
    assert_eq!(tx.pending_rev(), Rev(1));
    let e = rename(&tx, 0x1084, "alpha");
    assert!(tx.apply(e).unwrap().is_some());
    let c = tx.commit().unwrap();
    assert_eq!(
        (c.rev, c.tx, c.noop, c.edits.len()),
        (Rev(1), TxId(1), false, 1)
    );
    assert_eq!(c.label.as_str(), "test");
    assert_eq!(
        (c.source, c.session.as_str(), c.force),
        (Source::Agent, "mcp-1", false)
    );
    assert_eq!(c.start_band(), None);
    assert_eq!((p.rev(), p.last_tx()), (Rev(1), TxId(1)));
    // A no-op commit takes no transaction ID.
    let tx = agent(&mut p);
    let c = tx.commit().unwrap();
    assert!(c.noop);
    assert_eq!((c.rev, p.rev(), p.last_tx()), (Rev(1), Rev(1), TxId(1)));
    let mut tx = agent(&mut p);
    assert_eq!(tx.id(), TxId(2));
    let f = Edit::SetNoreturn {
        id: FuncId(ram(0x10c0)),
        noreturn: Some(tx.fact(true)),
    };
    tx.apply(f).unwrap();
    let e = rename(&tx, 0x1088, "beta");
    tx.apply(e).unwrap();
    let c = tx.commit().unwrap();
    assert_eq!((c.rev, c.tx, c.start_band()), (Rev(2), TxId(2), Some(100)));
}

#[test]
fn tx_drop_rolls_back() {
    let mut p = seeded();
    let before = hash(&p);
    {
        let mut tx = agent(&mut p);
        let e = rename(&tx, 0x1084, "alpha");
        tx.apply(e).unwrap();
        let func = base_func(&tx, 0x1140, 0x114f);
        tx.apply(Edit::CreateFunction(Box::new(FuncRecord {
            func,
            vars: Vec::new(),
            plate: None,
        })))
        .unwrap();
        let todo = note(&tx, 1, "check");
        tx.apply(Edit::WriteNote(Box::new(todo))).unwrap();
        let reference = tx.fact(Ref {
            key: RefKey {
                from: ram(0x1090),
                op_index: 0,
                to: ram(0x10c0),
                kind: RefType::Data,
            },
            primary: true,
        });
        tx.apply(Edit::AddRef { fact: reference }).unwrap();
        assert_eq!(tx.edits().len(), 4);
        assert_eq!(tx.program().name(ram(0x1084)).unwrap().text, "alpha");
        assert!(tx.program().func(FuncId(ram(0x1140))).is_some());
    }
    assert_eq!(hash(&p), before);
    assert_eq!(
        (p.rev(), p.last_tx(), p.events().len()),
        (Rev(0), TxId(0), 0)
    );
    let mut tx = agent(&mut p);
    let e = rename(&tx, 0x1084, "gamma");
    tx.apply(e).unwrap();
    tx.abort();
    assert_eq!(hash(&p), before);
}

#[test]
fn drop_during_panic_keeps_the_edits() {
    let mut p = seeded();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut tx = agent(&mut p);
        let e = rename(&tx, 0x1084, "alpha");
        tx.apply(e).unwrap();
        panic!("a tool panics inside the Tx");
    }));
    assert!(result.is_err());
    assert_eq!(p.name(ram(0x1084)).unwrap().text, "alpha");
    assert_eq!(p.rev(), Rev(0));
}

#[test]
fn nested_abort_poisons_tx() {
    let mut p = seeded();
    let before = hash(&p);
    let mut tx = agent(&mut p);
    let e = rename(&tx, 0x1084, "alpha");
    tx.apply(e).unwrap();
    {
        let mut n = tx.nest();
        let e = rename(n.tx(), 0x1088, "beta");
        assert!(n.apply(e).unwrap().is_some());
        n.abort();
    }
    assert!(tx.is_poisoned());
    assert_eq!(tx.edits().len(), 1);
    assert!(tx.program().primary_symbol(ram(0x1088)).is_none());
    let e = rename(&tx, 0x1094, "gamma");
    assert_eq!(tx.apply(e).err(), Some(EditError::Poisoned));
    assert_eq!(tx.commit().err(), Some(TxError::Poisoned));
    assert_eq!(hash(&p), before);
    assert_eq!(p.rev(), Rev(0));
    // A nested commit keeps its edits. A nested drop poisons the Tx.
    let mut tx = agent(&mut p);
    {
        let mut n = tx.nest();
        let mut inner = n.nest();
        let e = rename(inner.tx(), 0x1088, "beta");
        inner.apply(e).unwrap();
        inner.commit();
        n.commit();
    }
    assert!(!tx.is_poisoned());
    assert_eq!(tx.commit().unwrap().edits.len(), 1);
    let mut tx = agent(&mut p);
    {
        let mut n = tx.nest();
        let e = rename(n.tx(), 0x108c, "delta");
        n.apply(e).unwrap();
    }
    assert!(tx.is_poisoned());
}

#[test]
fn blocked_with_and_without_force() {
    let mut p = seeded();
    let imported = p
        .base()
        .symbols()
        .iter()
        .find(|s| s.primary && s.addr.is_ram())
        .cloned()
        .unwrap();
    let mut tx = agent(&mut p);
    let e = rename(&tx, imported.addr.off, "my_name");
    let Err(EditError::Blocked(b)) = tx.apply(e) else {
        panic!("an agent rename of an imported name needs force");
    };
    assert_eq!(b.current.source, Source::Imported);
    assert_eq!(b.value, Value::from(imported.name.value.clone()));
    assert_eq!(
        (b.attempted, b.force, b.force_applies()),
        (Source::Agent, false, true)
    );
    assert_eq!(
        EditError::Blocked(b).code(),
        ErrorCode::BlockedByHigherPrioritySource
    );
    tx.set_force(true);
    let e = rename(&tx, imported.addr.off, "my_name");
    let applied = tx.apply(e).unwrap().unwrap();
    let Edit::SetName {
        name: Some(old), ..
    } = &applied.inverse
    else {
        panic!("the inverse holds the imported name");
    };
    assert_eq!(old, &imported.name);
    let c = tx.commit().unwrap();
    assert!(c.force);
    let now = p.primary_symbol(imported.addr).unwrap();
    assert_eq!(
        (now.name.value.as_str(), now.name.source, now.name.force),
        ("my_name", Source::Agent, true)
    );
    // A user rename replaces the agent name. An agent write over it fails even with force.
    let mut tx = p.begin("rename", Source::User, session("cli")).unwrap();
    let e = rename(&tx, imported.addr.off, "user_name");
    tx.apply(e).unwrap();
    tx.commit().unwrap();
    let mut tx = agent(&mut p);
    tx.set_force(true);
    let e = rename(&tx, imported.addr.off, "again");
    let Err(EditError::Blocked(b)) = tx.apply(e) else {
        panic!("a user name blocks an agent write");
    };
    assert!(!b.force_applies());
    assert!(b.force);
}

/// Builds the edit of one step of the idempotence test for the Tx `tx`.
fn step(tx: &Tx<'_>, i: usize) -> Edit {
    let p = tx.program();
    let long = p.types().store().prim(Prim::Long);
    let fn_type = p
        .types()
        .store()
        .ids()
        .find(|id| p.types().sig(*id).is_some())
        .unwrap();
    let r = RefKey {
        from: ram(0x1090),
        op_index: 0,
        to: ram(0x10c0),
        kind: RefType::Read,
    };
    match i {
        0 => rename(tx, 0x1084, "alpha"),
        1 => Edit::SetComment {
            addr: ram(0x1080),
            kind: CommentKind::Eol,
            text: Some(tx.fact("hi".to_string())),
        },
        2 => Edit::SetVarFact {
            var: VarId {
                func: FuncId(ram(0x1080)),
                storage: Storage::Param(0),
            },
            field: VarField::Name(Some(tx.fact("x".to_string()))),
        },
        3 => Edit::AddRef {
            fact: tx.fact(Ref {
                key: r,
                primary: true,
            }),
        },
        4 => Edit::RemoveRef { key: r },
        5 => Edit::CreateFunction(Box::new(FuncRecord {
            func: base_func(tx, 0x1140, 0x1143),
            vars: Vec::new(),
            plate: None,
        })),
        6 => Edit::DeleteFunction {
            id: FuncId(ram(0x1140)),
            cascade: false,
        },
        7 => Edit::SetSignature {
            id: FuncId(ram(0x1080)),
            sig: Some(tx.fact(fn_type)),
        },
        8 => Edit::SetNoreturn {
            id: FuncId(ram(0x10c0)),
            noreturn: Some(tx.fact(true)),
        },
        9 => Edit::SetJumpTable {
            id: JumpTableId(ram(0x1144)),
            table: Some(tx.fact(JumpTable {
                base: None,
                entry_size: 0,
                count: 1,
                targets: vec![ram(0x1150)],
                method: JtMethod::Agent,
                resolved: true,
            })),
        },
        10 => Edit::SetFlowOverride {
            at: ram(0x1148),
            flow: Some(tx.fact(FlowOverride::CallAsJump)),
        },
        11 => Edit::SetDataDef {
            at: ram(0x4000),
            def: Some(tx.fact(DataDef { ty: long, len: 8 })),
        },
        12 => Edit::WriteNote(Box::new(note(tx, 1, "check"))),
        13 => Edit::DeleteNote { id: NoteId(1) },
        _ => Edit::ReplaceAnalysis(Box::new(analysis_set(p, 1))),
    }
}

#[test]
fn ac_127_edit_idempotent() {
    let mut p = seeded();
    for i in 0..15 {
        let source = if i == 14 {
            Source::Analysis
        } else {
            Source::Agent
        };
        let label = if i == 14 { "analysis" } else { "mcp-1" };
        for round in 0..2 {
            let rev = p.rev();
            let mut tx = p.begin("step", source, session(label)).unwrap();
            let e = step(&tx, i);
            let kind = e.kind();
            let applied = tx.apply(e).unwrap().is_some();
            let c = tx.commit().unwrap();
            if round == 0 {
                assert!(
                    applied && !c.noop,
                    "{kind}: the first apply changes the state"
                );
                assert_eq!(c.rev, Rev(rev.0 + 1), "{kind}");
            } else {
                assert!(!applied && c.noop, "{kind}: the second apply is a no-op");
                assert_eq!((c.rev, p.rev()), (rev, rev), "{kind}");
            }
        }
    }
    assert_eq!(p.rev(), Rev(15));
}

#[test]
fn replace_analysis_rollback() {
    let mut p = seeded();
    let old = p.analysis().clone();
    let new = analysis_set(&p, 1);
    {
        let mut tx = p
            .begin("analysis_run", Source::Analysis, session("analysis"))
            .unwrap();
        tx.apply(Edit::ReplaceAnalysis(Box::new(new.clone())))
            .unwrap();
        assert_eq!(tx.program().analysis(), &new);
    }
    assert_eq!(p.analysis(), &old);
    let mut tx = agent(&mut p);
    assert_eq!(
        tx.apply(Edit::ReplaceAnalysis(Box::new(new.clone()))).err(),
        Some(EditError::WrongLayer(Source::Agent))
    );
    drop(tx);
    let mut tx = p
        .begin("analysis_run", Source::Analysis, session("analysis"))
        .unwrap();
    tx.apply(Edit::ReplaceAnalysis(Box::new(new.clone())))
        .unwrap();
    let c = tx.commit().unwrap();
    assert_eq!(c.edits[0].inverse, Edit::ReplaceAnalysis(Box::new(old)));
    assert_eq!(p.analysis(), &new);
    assert_eq!(p.epoch(Table::Analysis), Rev(1));
    assert_eq!(p.epoch(Table::Functions), Rev(1));
    assert_eq!(p.epoch(Table::Notes), Rev(0));
    let kinds: Vec<Table> = p.events().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![Table::Analysis]);
}

/// Gives the seeded program with a full base function at `0x1140`. The function has parts,
/// a signature, a noreturn flag, two variables, a plate comment and an EOL comment.
fn full_function() -> (Program, Function, [VarId; 2]) {
    let mut p = seeded();
    let fn_type = func_type(&mut p);
    let long = p.types().store().prim(Prim::Long);
    let f = FuncId(ram(0x1140));
    let vars = [Storage::Param(0), Storage::Stack(-8)].map(|storage| VarId { func: f, storage });
    let mut tx = agent(&mut p);
    let mut func = base_func(&tx, 0x1140, 0x114f);
    func.parts = vec![Part {
        range: Range {
            first: 0x1140,
            last: 0x114f,
        },
        kind: PartKind::Main,
    }];
    func.sig = Some(tx.fact(fn_type));
    func.flags.noreturn = Some(tx.fact(false));
    tx.apply(Edit::CreateFunction(Box::new(FuncRecord {
        func: func.clone(),
        vars: Vec::new(),
        plate: None,
    })))
    .unwrap();
    for var in &vars {
        let name = Edit::SetVarFact {
            var: var.clone(),
            field: VarField::Name(Some(tx.fact("v".to_string()))),
        };
        tx.apply(name).unwrap();
        let ty = Edit::SetVarFact {
            var: var.clone(),
            field: VarField::Type(Some(tx.fact(long))),
        };
        tx.apply(ty).unwrap();
    }
    for kind in [CommentKind::Plate, CommentKind::Eol] {
        let comment = Edit::SetComment {
            addr: ram(0x1140),
            kind,
            text: Some(tx.fact(kind.name().to_string())),
        };
        tx.apply(comment).unwrap();
    }
    tx.commit().unwrap();
    (p, func, vars)
}

#[test]
fn delete_function_inverse_captures_side_effects() {
    let (mut p, func, vars) = full_function();
    let f = func.id();
    let before = hash(&p);
    let mut tx = agent(&mut p);
    let applied = tx
        .apply(Edit::DeleteFunction {
            id: f,
            cascade: true,
        })
        .unwrap()
        .unwrap()
        .clone();
    let Edit::CreateFunction(record) = &applied.inverse else {
        panic!("the inverse of a delete is a create");
    };
    assert_eq!(record.func, func);
    assert!(
        vars.iter()
            .all(|v| tx.program().base().vars().get(v).is_none())
    );
    let names: Vec<&VarId> = record.vars.iter().map(|(v, _)| v).collect();
    assert_eq!(names, vars.iter().collect::<Vec<_>>());
    assert!(
        record
            .vars
            .iter()
            .all(|(_, facts): &(VarId, VarFact)| facts.name.is_some() && facts.ty.is_some())
    );
    assert_eq!(
        record.plate.as_ref().map(|c| c.value.as_str()),
        Some("plate")
    );
    let program = tx.program();
    assert!(program.comment(ram(0x1140), CommentKind::Plate).is_none());
    assert!(program.comment(ram(0x1140), CommentKind::Eol).is_some());
    tx.commit().unwrap();
    // The inverse puts the function, its variables and its plate comment back.
    let label = SessionLabel::new("mcp-1").unwrap();
    let mut tx = p.begin("history_undo", Source::Agent, label).unwrap();
    tx.restore(applied.inverse.clone()).unwrap();
    tx.commit().unwrap();
    assert_eq!(hash(&p), before);
    // A delete without cascade keeps the variables and the plate comment.
    let mut tx = agent(&mut p);
    let a = tx
        .apply(Edit::DeleteFunction {
            id: f,
            cascade: false,
        })
        .unwrap()
        .unwrap();
    let Edit::CreateFunction(record) = &a.inverse else {
        panic!("the inverse of a delete is a create");
    };
    assert!(record.vars.is_empty() && record.plate.is_none());
    assert!(
        tx.program()
            .comment(ram(0x1140), CommentKind::Plate)
            .is_some()
    );
}
