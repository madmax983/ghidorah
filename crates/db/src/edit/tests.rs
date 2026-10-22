mod funcs;

use ghidorah_base::{Address, ErrorCode, FuncId, JumpTableId, NoteId, Range, Rev, Storage, VarId};
use ghidorah_kernel::RangeSet;
use ghidorah_types::{Prim, TypeId};

use super::{Edit, EditError, EditKind, FuncRecord, Layer, VarField};
use crate::comments::CommentKind;
use crate::fact::{Invalid, Origin};
use crate::funcs::{Function, StartReason};
use crate::jumptables::{JtMethod, JumpTable};
use crate::listing::DataDef;
use crate::notes::{Note, NoteKind, NoteStatus};
use crate::overrides::FlowOverride;
use crate::program::Program;
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::symbols::{SymKey, SymKind};
use crate::tests::{func_type, origin, ram, seeded, session};
use crate::tx::Tx;
use crate::why::FactKey;

fn agent(p: &mut Program) -> Tx<'_> {
    p.begin("test", Source::Agent, session("mcp-1")).unwrap()
}

fn name_edit(addr: Address, key: Option<SymKey>, name: Option<crate::Fact<String>>) -> Edit {
    Edit::SetName {
        addr,
        key,
        kind: SymKind::Label,
        primary: true,
        name,
        evidence: Vec::new(),
    }
}

#[test]
fn kinds_names_and_bands_match_the_design() {
    let bands = [
        (EditKind::SetName, None),
        (EditKind::SetComment, None),
        (EditKind::SetVarFact, None),
        (EditKind::AddRef, Some(100)),
        (EditKind::RemoveRef, Some(100)),
        (EditKind::CreateFunction, Some(100)),
        (EditKind::DeleteFunction, Some(100)),
        (EditKind::SetSignature, Some(800)),
        (EditKind::SetNoreturn, Some(100)),
        (EditKind::SetJumpTable, Some(100)),
        (EditKind::SetFlowOverride, Some(100)),
        (EditKind::SetDataDef, Some(100)),
        (EditKind::WriteNote, None),
        (EditKind::DeleteNote, None),
        (EditKind::ReplaceAnalysis, None),
    ];
    assert_eq!(bands.map(|(k, _)| k), EditKind::ALL);
    for (kind, band) in bands {
        assert_eq!(kind.band(), band, "{kind}");
        assert_eq!(EditKind::parse(kind.name()), Some(kind));
        assert_eq!(kind.to_string(), kind.name());
    }
    assert_eq!(EditKind::parse("setname"), None);
    assert_eq!(Layer::of(Source::Default), None);
    assert_eq!(Layer::of(Source::Imported), Some(Layer::Base));
    assert_eq!(
        Layer::of(Source::Analysis).map(Layer::name),
        Some("analysis")
    );
    assert_eq!(Layer::Base.to_string(), "base");
}

#[test]
fn keys_name_the_slots() {
    for (edit, want) in key_cases() {
        let mut want = want;
        want.sort();
        assert_eq!(edit.keys(), want, "{}", edit.kind());
    }
}

/// Gives a record at `0x1080` with a signature, one variable and a plate comment.
fn key_record(o: &Origin, var: &VarId) -> FuncRecord {
    let mut func = Function::new(ram(0x1080), StartReason::Agent, 100, Source::Agent);
    func.sig = Some(o.fact(TypeId::from_index(1)));
    FuncRecord {
        func,
        vars: vec![(var.clone(), crate::VarFact::default())],
        plate: Some(o.fact("p".to_string())),
    }
}

/// Gives one edit of each kind with the keys that it names.
fn key_cases() -> Vec<(Edit, Vec<FactKey>)> {
    let o = origin(Source::Agent, 1, "mcp-1");
    let f = FuncId(ram(0x1080));
    let key = RefKey {
        from: ram(0x1084),
        op_index: 0,
        to: ram(0x10c0),
        kind: RefType::Read,
    };
    let var = VarId {
        func: f,
        storage: Storage::Param(1),
    };
    let record = key_record(&o, &var);
    vec![
        (
            name_edit(ram(0x10), Some(SymKey(2)), None),
            vec![FactKey::Symbol(ram(0x10), SymKey(2))],
        ),
        (name_edit(ram(0x10), None, None), vec![]),
        (
            Edit::SetComment {
                addr: ram(0x10),
                kind: CommentKind::Pre,
                text: None,
            },
            vec![FactKey::Comment(ram(0x10), CommentKind::Pre)],
        ),
        (
            Edit::SetVarFact {
                var: var.clone(),
                field: VarField::Type(None),
            },
            vec![FactKey::Var(var.clone())],
        ),
        (
            Edit::AddRef {
                fact: o.fact(Ref { key, primary: true }),
            },
            vec![FactKey::Ref(key)],
        ),
        (Edit::RemoveRef { key }, vec![FactKey::Ref(key)]),
        (
            Edit::CreateFunction(Box::new(record)),
            vec![
                FactKey::Func(f),
                FactKey::Signature(f),
                FactKey::Comment(ram(0x1080), CommentKind::Plate),
                FactKey::Var(var),
            ],
        ),
        (
            Edit::DeleteFunction {
                id: f,
                cascade: true,
            },
            vec![FactKey::Func(f)],
        ),
        (
            Edit::SetSignature { id: f, sig: None },
            vec![FactKey::Signature(f)],
        ),
        (
            Edit::SetNoreturn {
                id: f,
                noreturn: None,
            },
            vec![FactKey::Noreturn(f)],
        ),
        (
            Edit::SetJumpTable {
                id: JumpTableId(ram(0x10)),
                table: None,
            },
            vec![FactKey::JumpTable(JumpTableId(ram(0x10)))],
        ),
        (
            Edit::SetFlowOverride {
                at: ram(0x10),
                flow: None,
            },
            vec![FactKey::FlowOverride(ram(0x10))],
        ),
        (
            Edit::SetDataDef {
                at: ram(0x10),
                def: None,
            },
            vec![FactKey::Data(0x10)],
        ),
        (
            Edit::DeleteNote { id: NoteId(3) },
            vec![FactKey::Note(NoteId(3))],
        ),
        (Edit::ReplaceAnalysis(std::sync::Arc::default()), vec![]),
    ]
}

#[test]
fn set_name_inverse_restores_aliases_and_keys() {
    let mut p = seeded();
    let at = ram(0x1084);
    let mut tx = agent(&mut p);
    for (key, n) in [(None, "first"), (Some(SymKey(1)), "second")] {
        let mut e = name_edit(at, key, Some(tx.fact(n.to_string())));
        if let Edit::SetName { primary, .. } = &mut e {
            *primary = key.is_none();
        }
        tx.apply(e).unwrap().unwrap();
    }
    let before = tx.program().state_hash().unwrap();
    // Remove the primary symbol: the alias takes the flag.
    let applied = tx
        .apply(name_edit(at, None, None))
        .unwrap()
        .unwrap()
        .clone();
    let alias = tx.program().primary_symbol(at).unwrap();
    assert_eq!(
        (alias.key, alias.name.value.as_str()),
        (SymKey(1), "second")
    );
    let Edit::SetName {
        key, primary, name, ..
    } = &applied.inverse
    else {
        panic!("the inverse is a SetName");
    };
    assert_eq!((*key, *primary), (Some(SymKey(0)), true));
    assert_eq!(name.as_ref().map(|f| f.value.as_str()), Some("first"));
    tx.restore(applied.inverse).unwrap().unwrap();
    assert_eq!(tx.program().state_hash().unwrap(), before);
    assert_eq!(tx.program().primary_symbol(at).unwrap().key, SymKey(0));
    // A duplicate name at the address is not valid.
    let dup = name_edit(at, None, Some(tx.fact("second".to_string())));
    assert_eq!(
        tx.apply(dup).err(),
        Some(EditError::Invalid(Invalid::DuplicateName(
            "second".to_string()
        )))
    );
    let empty = name_edit(at, None, Some(tx.fact(String::new())));
    assert_eq!(
        tx.apply(empty).err(),
        Some(EditError::Invalid(Invalid::EmptyName))
    );
    let mut long = name_edit(at, None, Some(tx.fact("ok".to_string())));
    if let Edit::SetName { evidence, .. } = &mut long {
        *evidence = vec!["x".to_string(); 17];
    }
    assert!(matches!(
        tx.apply(long).err(),
        Some(EditError::Invalid(Invalid::TooMany { count: 17, .. }))
    ));
}

#[test]
fn forward_edits_need_the_tx_origin_and_layer() {
    let mut p = seeded();
    let mut tx = agent(&mut p);
    let other = origin(Source::Agent, 99, "mcp-1");
    let e = name_edit(ram(0x1084), None, Some(other.fact("x".to_string())));
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::Origin(FactKey::Symbol(ram(0x1084), SymKey(0))))
    );
    let e = Edit::SetComment {
        addr: ram(0x1084),
        kind: CommentKind::Eol,
        text: Some(Origin::analysis().fact("x".to_string())),
    };
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::WrongLayer(Source::Analysis))
    );
    // An exact edit skips the origin check but keeps the layer check.
    let e = Edit::SetComment {
        addr: ram(0x1084),
        kind: CommentKind::Eol,
        text: Some(other.fact("x".to_string())),
    };
    assert!(tx.restore(e).unwrap().is_some());
    let e = Edit::SetComment {
        addr: ram(0x1084),
        kind: CommentKind::Eol,
        text: Some(Origin::analysis().fact("x".to_string())),
    };
    assert_eq!(
        tx.restore(e).err(),
        Some(EditError::WrongLayer(Source::Analysis))
    );
    // An empty comment text removes the comment.
    let e = Edit::SetComment {
        addr: ram(0x1084),
        kind: CommentKind::Eol,
        text: Some(tx.fact(String::new())),
    };
    let a = tx.apply(e).unwrap().unwrap();
    assert!(matches!(&a.edit, Edit::SetComment { text: None, .. }));
    assert!(
        tx.program()
            .comment(ram(0x1084), CommentKind::Eol)
            .is_none()
    );
}

#[test]
fn exact_restore_skips_the_write_rule() {
    let mut p = seeded();
    let mut tx = p.begin("rename", Source::User, session("cli")).unwrap();
    let e = name_edit(ram(0x1084), None, Some(tx.fact("user".to_string())));
    tx.apply(e).unwrap();
    tx.commit().unwrap();
    let mut tx = agent(&mut p);
    let lower = origin(Source::Agent, 7, "mcp-2");
    let e = name_edit(
        ram(0x1084),
        Some(SymKey(0)),
        Some(lower.fact("agent".to_string())),
    );
    tx.restore(e).unwrap().unwrap();
    let s = tx.program().primary_symbol(ram(0x1084)).unwrap();
    assert_eq!((s.name.source, s.name.tx.0), (Source::Agent, 7));
}

#[test]
fn refs_need_a_code_unit_or_data_start() {
    let mut p = seeded();
    let mut tx = agent(&mut p);
    let key = |from| RefKey {
        from: ram(from),
        op_index: 0,
        to: ram(0x10c0),
        kind: RefType::Data,
    };
    for (from, ok) in [(0x1090, true), (0x1091, false), (0x2000, false)] {
        let r = tx.fact(Ref {
            key: key(from),
            primary: true,
        });
        let got = tx.apply(Edit::AddRef { fact: r });
        if ok {
            assert!(got.unwrap().is_some());
        } else {
            assert_eq!(got.err(), Some(EditError::NotCode(ram(from))));
        }
    }
    let long = tx.program().types().store().prim(Prim::Long);
    let d = Edit::SetDataDef {
        at: ram(0x4000),
        def: Some(tx.fact(DataDef { ty: long, len: 8 })),
    };
    tx.apply(d).unwrap().unwrap();
    let r = tx.fact(Ref {
        key: key(0x4000),
        primary: false,
    });
    assert!(tx.apply(Edit::AddRef { fact: r }).unwrap().is_some());
    let a = tx
        .apply(Edit::RemoveRef { key: key(0x4000) })
        .unwrap()
        .unwrap();
    assert!(matches!(&a.inverse, Edit::AddRef { fact } if fact.value.key == key(0x4000)));
    assert!(
        tx.apply(Edit::RemoveRef { key: key(0x4000) })
            .unwrap()
            .is_none()
    );
}

#[test]
fn targets_need_code_or_an_import() {
    let mut p = seeded();
    let mut tx = agent(&mut p);
    let ext = tx.program().imports().values().next().unwrap().ext;
    for (target, ok) in [
        (ram(0x1150), true),
        (ram(0x1000), true),
        (ext, true),
        (ram(0x1151), false),
        (ram(0x2000), false),
        (Address::external(999), false),
    ] {
        let table = tx.fact(JumpTable {
            base: None,
            entry_size: 0,
            count: 1,
            targets: vec![target],
            method: JtMethod::Agent,
            resolved: true,
        });
        let e = Edit::SetJumpTable {
            id: JumpTableId(ram(0x1144)),
            table: Some(table),
        };
        assert_eq!(tx.apply(e).is_ok(), ok, "{target}");
        assert_eq!(tx.program().is_code_target(target), ok, "{target}");
        let flow = tx.fact(FlowOverride::IndirectTargets(vec![
            target,
            ram(0x1150),
            target,
        ]));
        let e = Edit::SetFlowOverride {
            at: ram(0x1148),
            flow: Some(flow),
        };
        match tx.apply(e) {
            Ok(applied) => {
                assert!(ok);
                let Some(applied) = applied else { continue };
                let Edit::SetFlowOverride {
                    flow: Some(fact), ..
                } = &applied.edit
                else {
                    panic!("the edit keeps its kind");
                };
                let FlowOverride::IndirectTargets(list) = &fact.value else {
                    panic!("the override keeps its kind");
                };
                assert!(
                    list.windows(2).all(|w| w[0] < w[1]),
                    "targets are sorted: {list:?}"
                );
            }
            Err(err) => {
                assert!(!ok);
                assert_eq!(err, EditError::BadTarget(target));
                assert_eq!(err.code(), ErrorCode::InvalidArgument);
            }
        }
    }
}

#[test]
fn types_must_exist_and_signatures_need_function_types() {
    let mut p = seeded();
    let fn_type = func_type(&mut p);
    let long = p.types().store().prim(Prim::Long);
    let mut tx = agent(&mut p);
    let f = FuncId(ram(0x1080));
    let unknown = TypeId::from_index(1_000_000);
    let e = Edit::SetSignature {
        id: f,
        sig: Some(tx.fact(long)),
    };
    assert_eq!(tx.apply(e).err(), Some(EditError::NotFuncType(long)));
    let e = Edit::SetSignature {
        id: f,
        sig: Some(tx.fact(unknown)),
    };
    assert_eq!(tx.apply(e).err(), Some(EditError::UnknownType(unknown)));
    let e = Edit::SetDataDef {
        at: ram(0x4000),
        def: Some(tx.fact(DataDef {
            ty: unknown,
            len: 8,
        })),
    };
    assert_eq!(tx.apply(e).err(), Some(EditError::UnknownType(unknown)));
    let e = Edit::SetDataDef {
        at: Address::external(1),
        def: Some(tx.fact(DataDef { ty: long, len: 8 })),
    };
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::Invalid(Invalid::NotRam(Address::external(1))))
    );
    let var = VarId {
        func: f,
        storage: Storage::Ret,
    };
    let e = Edit::SetVarFact {
        var,
        field: VarField::Type(Some(tx.fact(unknown))),
    };
    assert_eq!(tx.apply(e).err(), Some(EditError::UnknownType(unknown)));
    // No function at all.
    let e = Edit::SetSignature {
        id: FuncId(ram(0x1144)),
        sig: Some(tx.fact(fn_type)),
    };
    assert_eq!(
        tx.apply(e).err(),
        Some(EditError::Invalid(Invalid::NoFunc(FuncId(ram(0x1144)))))
    );
    assert!(
        tx.apply(Edit::SetSignature {
            id: FuncId(ram(0x1144)),
            sig: None,
        })
        .unwrap()
        .is_none()
    );
}

#[test]
fn signature_on_a_discovered_function_makes_a_holder_record() {
    let mut p = seeded();
    let fn_type = func_type(&mut p);
    let before = p.state_hash().unwrap();
    let f = FuncId(ram(0x10c0));
    let mut tx = agent(&mut p);
    let e = Edit::SetSignature {
        id: f,
        sig: Some(tx.fact(fn_type)),
    };
    let sig = tx.apply(e).unwrap().unwrap().clone();
    assert_eq!(
        sig.inverse,
        Edit::DeleteFunction {
            id: f,
            cascade: false
        }
    );
    let holder = tx.program().base().funcs().get(f).unwrap();
    assert_eq!(holder.source, Source::Agent);
    assert_eq!(holder.start_reason, StartReason::Call);
    let view = tx.program().func(f).unwrap();
    assert_eq!(view.sig.map(|fact| fact.value), Some(fn_type));
    assert_eq!(
        view.func.body,
        tx.program().analysis().funcs().get(f).unwrap().body
    );
    let e = Edit::SetNoreturn {
        id: FuncId(ram(0x1100)),
        noreturn: Some(tx.fact(true)),
    };
    let flag = tx.apply(e).unwrap().unwrap().clone();
    assert_eq!(
        flag.inverse,
        Edit::DeleteFunction {
            id: FuncId(ram(0x1100)),
            cascade: false
        }
    );
    tx.restore(flag.inverse).unwrap();
    tx.restore(sig.inverse).unwrap();
    assert_eq!(tx.program().state_hash().unwrap(), before);
}

#[test]
fn create_with_listed_slots_needs_empty_slots() {
    let mut p = seeded();
    let mut tx = agent(&mut p);
    let f = FuncId(ram(0x1140));
    let var = VarId {
        func: f,
        storage: Storage::Param(0),
    };
    let e = Edit::SetVarFact {
        var: var.clone(),
        field: VarField::Name(Some(tx.fact("old".to_string()))),
    };
    tx.apply(e).unwrap();
    let mut func = Function::new(ram(0x1140), StartReason::Agent, 100, Source::Agent);
    func.body = RangeSet::from_ranges(&[Range {
        first: 0x1140,
        last: 0x1143,
    }]);
    let other = VarId {
        func: f,
        storage: Storage::Param(1),
    };
    let rec = FuncRecord {
        func: func.clone(),
        vars: vec![(
            other,
            crate::VarFact {
                name: Some(tx.fact("new".to_string())),
                ty: None,
            },
        )],
        plate: None,
    };
    assert_eq!(
        tx.apply(Edit::CreateFunction(Box::new(rec))).err(),
        Some(EditError::Occupied(FactKey::Var(var)))
    );
    // A create without listed slots keeps the old variable facts. Its inverse keeps them too.
    let rec = FuncRecord {
        func,
        vars: Vec::new(),
        plate: None,
    };
    let a = tx
        .apply(Edit::CreateFunction(Box::new(rec.clone())))
        .unwrap()
        .unwrap();
    assert_eq!(
        a.inverse,
        Edit::DeleteFunction {
            id: f,
            cascade: false
        }
    );
    assert!(
        tx.apply(Edit::CreateFunction(Box::new(rec.clone())))
            .unwrap()
            .is_none()
    );
    let mut changed = rec;
    changed.func.confidence = 5;
    assert_eq!(
        tx.apply(Edit::CreateFunction(Box::new(changed))).err(),
        Some(EditError::Invalid(Invalid::FuncExists(f)))
    );
    let mut wrong = Function::new(ram(0x1170), StartReason::Agent, 100, Source::User);
    wrong.body = RangeSet::from_ranges(&[Range::single(0x1170)]);
    let rec = FuncRecord {
        func: wrong,
        vars: Vec::new(),
        plate: None,
    };
    assert_eq!(
        tx.apply(Edit::CreateFunction(Box::new(rec))).err(),
        Some(EditError::Origin(FactKey::Func(FuncId(ram(0x1170)))))
    );
}

#[test]
fn note_edits_check_origin_rev_and_rank() {
    let mut p = seeded();
    let mut tx = p.begin("note_write", Source::User, session("cli")).unwrap();
    let mut n = Note {
        id: NoteId(1),
        kind: NoteKind::Finding,
        text: "user note".to_string(),
        at: None,
        func: None,
        status: NoteStatus::Open,
        tags: Vec::new(),
        evidence: Vec::new(),
        lift_ver: None,
        claims: Vec::new(),
        set: None,
        src: Source::User,
        session: session("cli"),
        rev: Rev(1),
    };
    let mut stale = n.clone();
    stale.rev = Rev(7);
    assert_eq!(
        tx.apply(Edit::WriteNote(Box::new(stale))).err(),
        Some(EditError::Origin(FactKey::Note(NoteId(1))))
    );
    let a = tx
        .apply(Edit::WriteNote(Box::new(n.clone())))
        .unwrap()
        .unwrap();
    assert_eq!(a.inverse, Edit::DeleteNote { id: NoteId(1) });
    tx.commit().unwrap();
    let mut tx = agent(&mut p);
    n.src = Source::Agent;
    n.session = session("mcp-1");
    n.rev = Rev(2);
    n.text = "agent text".to_string();
    let Err(EditError::Blocked(b)) = tx.apply(Edit::WriteNote(Box::new(n))) else {
        panic!("a user note blocks an agent write");
    };
    assert_eq!(b.key, FactKey::Note(NoteId(1)));
    assert_eq!(b.current.source, Source::User);
    let Err(EditError::Blocked(_)) = tx.apply(Edit::DeleteNote { id: NoteId(1) }) else {
        panic!("a user note blocks an agent delete");
    };
    assert!(
        tx.apply(Edit::DeleteNote { id: NoteId(5) })
            .unwrap()
            .is_none()
    );
    drop(tx);
    let mut analysis = p
        .begin("analysis_run", Source::Analysis, session("analysis"))
        .unwrap();
    assert_eq!(
        analysis.apply(Edit::DeleteNote { id: NoteId(1) }).err(),
        Some(EditError::WrongLayer(Source::Analysis))
    );
}

#[test]
fn error_codes_and_texts() {
    let all = [
        (
            EditError::Invalid(Invalid::EmptyName),
            ErrorCode::InvalidArgument,
        ),
        (
            EditError::Origin(FactKey::Entry(1)),
            ErrorCode::InvalidArgument,
        ),
        (
            EditError::WrongLayer(Source::Agent),
            ErrorCode::InvalidArgument,
        ),
        (EditError::NotCode(ram(1)), ErrorCode::InvalidArgument),
        (EditError::BadTarget(ram(1)), ErrorCode::InvalidArgument),
        (
            EditError::UnknownType(TypeId::from_index(1)),
            ErrorCode::NotFound,
        ),
        (
            EditError::NotFuncType(TypeId::from_index(1)),
            ErrorCode::InvalidArgument,
        ),
        (EditError::Occupied(FactKey::Entry(1)), ErrorCode::Conflict),
        (EditError::Poisoned, ErrorCode::Conflict),
    ];
    for (e, code) in all {
        assert_eq!(e.code(), code, "{e}");
        assert!(
            e.to_string().ends_with('.') || e.to_string().ends_with(')'),
            "{e}"
        );
    }
    let _ = Origin::load();
}
