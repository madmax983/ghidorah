//! Rule 6 over premises of every key kind.

use ghidorah_base::{
    ExportId, FuncId, ImportId, JumpTableId, NoteId, Rev, Storage, StringId, VarId,
};
use ghidorah_types::Prim;

use crate::comments::CommentKind;
use crate::edit::{Edit, VarField};
use crate::invariants::Violation;
use crate::listing::{CodeUnit, DataDef, FlowKind};
use crate::notes::{Note, NoteKind, NoteStatus};
use crate::overrides::FlowOverride;
use crate::program::Program;
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::symbols::SymKey;
use crate::tests::{JUMP, STRING, func_type, ram, seeded, session};
use crate::why::{FactKey, RuleCode, Why};

fn read_key(from: u64) -> RefKey {
    RefKey {
        from: ram(from),
        op_index: 0,
        to: ram(0x10c0),
        kind: RefType::Read,
    }
}

fn var() -> VarId {
    VarId {
        func: FuncId(ram(0x1080)),
        storage: Storage::Param(0),
    }
}

/// Commits one base fact of each kind that a premise can name.
fn with_base_facts() -> Program {
    let mut p = seeded();
    let fn_type = func_type(&mut p);
    let long = p.types().store().prim(Prim::Long);
    let mut tx = p.begin("setup", Source::Agent, session("mcp-1")).unwrap();
    let note = Note {
        id: NoteId(1),
        kind: NoteKind::Note,
        text: "n".to_string(),
        at: None,
        func: None,
        status: NoteStatus::Open,
        tags: Vec::new(),
        evidence: Vec::new(),
        lift_ver: None,
        claims: Vec::new(),
        set: None,
        src: Source::Agent,
        session: session("mcp-1"),
        rev: Rev(1),
    };
    let edits = vec![
        Edit::SetDataDef {
            at: ram(0x4000),
            def: Some(tx.fact(DataDef { ty: long, len: 8 })),
        },
        Edit::SetComment {
            addr: ram(0x1084),
            kind: CommentKind::Eol,
            text: Some(tx.fact("c".to_string())),
        },
        Edit::SetVarFact {
            var: var(),
            field: VarField::Name(Some(tx.fact("argc".to_string()))),
        },
        Edit::AddRef {
            fact: tx.fact(Ref {
                key: read_key(0x1090),
                primary: true,
            }),
        },
        Edit::SetFlowOverride {
            at: ram(0x1094),
            flow: Some(tx.fact(FlowOverride::CallAsJump)),
        },
        Edit::SetSignature {
            id: FuncId(ram(0x1080)),
            sig: Some(tx.fact(fn_type)),
        },
        Edit::SetNoreturn {
            id: FuncId(ram(0x10c0)),
            noreturn: Some(tx.fact(true)),
        },
        Edit::WriteNote(Box::new(note)),
    ];
    for e in edits {
        tx.apply(e).unwrap().unwrap();
    }
    tx.commit().unwrap();
    p
}

#[test]
fn premises_resolve_for_every_key_kind() {
    let mut p = with_base_facts();
    let import = p.imports().keys().next().cloned().unwrap();
    let reloc = p.binary().relocs.first().map(|r| r.offset).unwrap();
    let fde = p.binary().fdes.first().map(|f| f.range.first).unwrap();
    let sym = p
        .base()
        .symbols()
        .iter()
        .next()
        .map(|s| (s.addr, s.key))
        .unwrap();
    let present = vec![
        FactKey::CodeUnit(0x1080),
        FactKey::Data(0x4000),
        FactKey::Symbol(sym.0, sym.1),
        FactKey::Func(FuncId(ram(0x1080))),
        FactKey::Signature(FuncId(ram(0x1080))),
        FactKey::Noreturn(FuncId(ram(0x10c0))),
        FactKey::Ref(read_key(0x1090)),
        FactKey::Comment(ram(0x1084), CommentKind::Eol),
        FactKey::JumpTable(JumpTableId(ram(JUMP))),
        FactKey::FlowOverride(ram(0x1094)),
        FactKey::Str(StringId(ram(STRING))),
        FactKey::Var(var()),
        FactKey::Import(import),
        FactKey::Entry(0x1090),
        FactKey::Reloc(reloc),
        FactKey::Fde(fde),
        FactKey::Note(NoteId(1)),
    ];
    let absent = vec![
        FactKey::CodeUnit(0x9000),
        FactKey::Data(0x4100),
        FactKey::Symbol(ram(0x9000), SymKey(0)),
        FactKey::Func(FuncId(ram(0x9000))),
        FactKey::Signature(FuncId(ram(0x1100))),
        FactKey::Noreturn(FuncId(ram(0x1100))),
        FactKey::Ref(read_key(0x1098)),
        FactKey::Comment(ram(0x9000), CommentKind::Eol),
        FactKey::JumpTable(JumpTableId(ram(0x9000))),
        FactKey::FlowOverride(ram(0x9000)),
        FactKey::Str(StringId(ram(0x9000))),
        FactKey::Var(VarId {
            func: FuncId(ram(0x9000)),
            storage: Storage::Ret,
        }),
        FactKey::Import(ImportId::elf("nope").unwrap()),
        FactKey::Export(ExportId::by_name("main").unwrap()),
        FactKey::Entry(0x9000),
        FactKey::Reloc(0x1),
        FactKey::Fde(0x1),
        FactKey::Note(NoteId(99)),
    ];
    let layer = p.layer_mut(Source::Analysis).unwrap();
    for (i, premise) in present.iter().chain(&absent).enumerate() {
        let at = 0x1180 + 4 * u64::try_from(i).unwrap();
        let unit = CodeUnit::Insn {
            len: 4,
            flow: FlowKind::Seq,
            flags: 0,
        };
        layer.listing.insert_unit(at, unit).unwrap();
        let why = Why {
            rule: RuleCode::new("R_TEST_PREMISE").unwrap(),
            premises: vec![premise.clone()],
        };
        layer.why.insert(FactKey::CodeUnit(at), why).unwrap();
    }
    let missing: Vec<FactKey> = p
        .check_invariants()
        .into_iter()
        .filter_map(|v| match v {
            Violation::Premise { premise, .. } => Some(premise),
            _ => None,
        })
        .collect();
    assert_eq!(missing, absent);
}
