//! The refused function edits and the exact symbol inserts.

use ghidorah_base::{FuncId, Range, Storage, VarId};
use ghidorah_kernel::RangeSet;
use ghidorah_types::TypeId;

use crate::comments::CommentKind;
use crate::edit::{Edit, EditError, FuncRecord, VarField};
use crate::fact::{Invalid, Origin};
use crate::funcs::{Function, StartReason};
use crate::source::Source;
use crate::symbols::{SymKey, SymKind};
use crate::tests::{func_type, origin, ram, seeded, session};
use crate::vars::VarFact;
use crate::why::FactKey;

fn record(func: Function, vars: Vec<(VarId, VarFact)>, plate: Option<crate::Fact<String>>) -> Edit {
    Edit::CreateFunction(Box::new(FuncRecord { func, vars, plate }))
}

fn func(entry: u64, source: Source) -> Function {
    let mut f = Function::new(ram(entry), StartReason::Agent, 100, source);
    f.body = RangeSet::from_ranges(&[Range {
        first: entry,
        last: entry + 3,
    }]);
    f
}

#[test]
fn function_edits_refuse_bad_records() {
    let mut p = seeded();
    let mut tx = p
        .begin("func_edit", Source::Agent, session("mcp-1"))
        .unwrap();
    let id = FuncId(ram(0x1140));
    let e = record(func(0x1140, Source::Analysis), Vec::new(), None);
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::WrongLayer(Source::Analysis))
    );
    let other = VarId {
        func: FuncId(ram(0x1080)),
        storage: Storage::Ret,
    };
    let e = record(
        func(0x1140, Source::Agent),
        vec![(other.clone(), VarFact::default())],
        None,
    );
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::Invalid(Invalid::NoFunc(other.func)))
    );
    let mine = VarId {
        func: id,
        storage: Storage::Ret,
    };
    let unknown = VarFact {
        name: None,
        ty: Some(tx.fact(TypeId::from_index(999_999))),
    };
    let e = record(
        func(0x1140, Source::Agent),
        vec![(mine.clone(), unknown)],
        None,
    );
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::UnknownType(TypeId::from_index(999_999)))
    );
    // A listed name that the variable table refuses leaves no function behind.
    let empty = VarFact {
        name: Some(tx.fact(String::new())),
        ty: None,
    };
    let before = tx.program().state_hash().unwrap();
    let e = record(func(0x1140, Source::Agent), vec![(mine, empty)], None);
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::Invalid(Invalid::EmptyName))
    );
    assert_eq!(tx.program().state_hash().unwrap(), before);
    // A listed plate comment needs an empty plate slot.
    let plate = Edit::SetComment {
        addr: ram(0x1140),
        kind: CommentKind::Plate,
        text: Some(tx.fact("old".to_string())),
    };
    tx.apply(plate).unwrap();
    let e = record(
        func(0x1140, Source::Agent),
        Vec::new(),
        Some(tx.fact("new".to_string())),
    );
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::Occupied(FactKey::Comment(
            ram(0x1140),
            CommentKind::Plate
        )))
    );
    tx.commit().unwrap();
}

#[test]
fn cascading_delete_follows_the_write_rule() {
    let mut p = seeded();
    let mut tx = p
        .begin("func_edit", Source::Agent, session("mcp-1"))
        .unwrap();
    let e = record(func(0x1140, Source::Agent), Vec::new(), None);
    tx.apply(e).unwrap();
    let name = Edit::SetVarFact {
        var: VarId {
            func: FuncId(ram(0x1140)),
            storage: Storage::Param(0),
        },
        field: VarField::Name(Some(tx.fact("n".to_string()))),
    };
    tx.apply(name).unwrap();
    tx.commit().unwrap();
    let mut tx = p
        .begin("comment_set", Source::User, session("cli"))
        .unwrap();
    let plate = Edit::SetComment {
        addr: ram(0x1140),
        kind: CommentKind::Plate,
        text: Some(tx.fact("user".to_string())),
    };
    tx.apply(plate).unwrap();
    tx.commit().unwrap();
    let mut tx = p
        .begin("func_edit", Source::Agent, session("mcp-1"))
        .unwrap();
    let delete = Edit::DeleteFunction {
        id: FuncId(ram(0x1140)),
        cascade: true,
    };
    let Err(EditError::Blocked(blocked)) = tx.apply(delete) else {
        panic!("a user plate comment blocks an agent cascade");
    };
    assert_eq!(
        blocked.key,
        FactKey::Comment(ram(0x1140), CommentKind::Plate)
    );
    assert!(EditError::Blocked(blocked).to_string().contains("user"));
    drop(tx);
    // A user deletes the function and its plate comment.
    let mut tx = p.begin("func_edit", Source::User, session("cli")).unwrap();
    let delete = Edit::DeleteFunction {
        id: FuncId(ram(0x1140)),
        cascade: true,
    };
    let applied = tx.apply(delete).unwrap().unwrap();
    let Edit::CreateFunction(rec) = &applied.inverse else {
        panic!("the inverse of a delete is a create");
    };
    assert_eq!((rec.vars.len(), rec.plate.is_some()), (1, true));
}

#[test]
fn analysis_signature_needs_an_analysis_record() {
    let mut p = seeded();
    let fn_type = func_type(&mut p);
    let mut tx = p
        .begin("analysis_run", Source::Analysis, session("analysis"))
        .unwrap();
    let id = FuncId(ram(0x1144));
    let e = Edit::SetSignature {
        id,
        sig: Some(tx.fact(fn_type)),
    };
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::Invalid(Invalid::NoFunc(id)))
    );
    let e = Edit::SetNoreturn {
        id,
        noreturn: Some(tx.fact(true)),
    };
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::Invalid(Invalid::NoFunc(id)))
    );
    let e = Edit::SetNoreturn { id, noreturn: None };
    assert!(tx.apply(e).unwrap().is_none());
    let found = FuncId(ram(0x1080));
    let e = Edit::SetNoreturn {
        id: found,
        noreturn: Some(tx.fact(true)),
    };
    let a = tx.apply(e).unwrap().unwrap();
    assert_eq!(
        a.inverse,
        Edit::SetNoreturn {
            id: found,
            noreturn: None
        }
    );
}

#[test]
fn exact_symbol_inserts_keep_one_primary() {
    let mut p = seeded();
    let mut tx = p
        .begin("history_undo", Source::Agent, session("mcp-1"))
        .unwrap();
    let o: Origin = origin(Source::Agent, 3, "mcp-1");
    let at = ram(0x1088);
    // A non-primary insert at an empty address becomes primary.
    let e = Edit::SetName {
        addr: at,
        key: Some(SymKey(4)),
        kind: SymKind::Label,
        primary: false,
        name: Some(o.fact("only".to_string())),
        evidence: Vec::new(),
    };
    tx.restore(e).unwrap();
    let s = tx.program().primary_symbol(at).unwrap();
    assert_eq!((s.key, s.primary), (SymKey(4), true));
    // An exact rename with an equal fact is a no-op.
    let same = Edit::SetName {
        addr: at,
        key: Some(SymKey(4)),
        kind: SymKind::Label,
        primary: true,
        name: Some(o.fact("only".to_string())),
        evidence: Vec::new(),
    };
    assert!(tx.restore(same).unwrap().is_none());
}

#[test]
fn regress_create_keeps_a_plate_comment() {
    let mut p = seeded();
    let mut tx = p
        .begin("comment_set", Source::Agent, session("mcp-1"))
        .unwrap();
    let text = tx.fact("a plate".to_string());
    tx.apply(Edit::SetComment {
        addr: ram(0x1140),
        kind: CommentKind::Plate,
        text: Some(text),
    })
    .unwrap();
    tx.commit().unwrap();
    let before = p.state_hash().unwrap();
    let mut tx = p
        .begin("func_edit", Source::Agent, session("mcp-1"))
        .unwrap();
    // A record with no plate leaves the plate slot alone.
    let applied = tx
        .apply(record(func(0x1140, Source::Agent), Vec::new(), None))
        .unwrap()
        .cloned()
        .unwrap();
    tx.commit().unwrap();
    let plate = p.base().comments().get(ram(0x1140), CommentKind::Plate);
    assert!(plate.is_some(), "the create keeps the plate");
    let mut tx = p
        .begin("history_undo", Source::Agent, session("mcp-1"))
        .unwrap();
    let undo = tx.restore(applied.inverse).unwrap().cloned().unwrap();
    tx.commit().unwrap();
    assert_eq!(p.state_hash().unwrap(), before, "the inverse is exact");
    let mut tx = p
        .begin("history_undo", Source::Agent, session("mcp-1"))
        .unwrap();
    tx.restore(undo.inverse).unwrap();
    tx.commit().unwrap();
    let plate = p.base().comments().get(ram(0x1140), CommentKind::Plate);
    assert!(plate.is_some(), "the redo keeps the plate");
}
