use ghidorah_base::{
    Address, ExportId, FuncId, ImportId, JumpTableId, NoteId, Range, RegVar, Rev, SetName, Storage,
    StringId, TxId, VarId, WarningCode,
};
use ghidorah_json::{DecodeKind, Limits, Value, parse, write, write_jcs};
use ghidorah_kernel::RangeSet;
use ghidorah_types::TypeId;

use super::{
    CodecError, Reason, edit_from_json, edit_to_json, facts, key_from_json, key_to_json,
    notes_from_json, notes_to_json, progress_from_json, progress_to_json, tables_from_json,
    tables_to_json,
};
use crate::comments::CommentKind;
use crate::edit::{Edit, EditKind, FuncRecord, VarField};
use crate::fact::{Fact, Origin};
use crate::funcs::{Caveat, Function, Part, PartKind, StartReason};
use crate::jumptables::{JtMethod, JumpTable};
use crate::listing::DataDef;
use crate::notes::{Claim, Note, NoteKind, NoteSet, NoteStatus, SetMembers};
use crate::overrides::FlowOverride;
use crate::progress::{FuncProgress, Mark};
use crate::refs::{Ref, RefKey, RefType};
use crate::source::Source;
use crate::symbols::{SymKey, SymKind};
use crate::test_support::{origin, ram, seeded, session};
use crate::vars::VarFact;
use crate::why::FactKey;

fn agent() -> Origin {
    let mut o = origin(Source::Agent, 42, "mcp-1");
    o.force = true;
    o
}

fn var(storage: Storage) -> VarId {
    VarId {
        func: FuncId(ram(0x1080)),
        storage,
    }
}

fn record() -> FuncRecord {
    let o = agent();
    let mut func = Function::new(ram(0x1140), StartReason::Agent, 77, Source::Agent);
    func.body = RangeSet::from_ranges(&[
        Range {
            first: 0x1140,
            last: 0x114f,
        },
        Range {
            first: 0x2000,
            last: u64::MAX,
        },
    ]);
    func.parts = vec![
        Part {
            range: Range {
                first: 0x1140,
                last: 0x114f,
            },
            kind: PartKind::Main,
        },
        Part {
            range: Range {
                first: 0x2000,
                last: u64::MAX,
            },
            kind: PartKind::Cold,
        },
    ];
    func.sig = Some(o.fact(TypeId::from_index(30)));
    func.flags.noreturn = Some(o.fact(true));
    func.flags.thunk = true;
    func.flags.varargs = true;
    func.caveats = vec![
        Caveat {
            code: WarningCode::NoreturnSuspect,
            at: Some(ram(0x1144)),
            remedy: Some("func_edit { action: \"set_noreturn\" }".to_string()),
        },
        Caveat {
            code: WarningCode::SpMismatch,
            at: None,
            remedy: None,
        },
    ];
    FuncRecord {
        func,
        vars: vec![
            (
                var(Storage::Param(0)),
                VarFact {
                    name: Some(o.fact("argc".to_string())),
                    ty: Some(o.fact(TypeId::from_index(7))),
                },
            ),
            (
                var(Storage::Reg(RegVar::new("rax", 0x1144).unwrap())),
                VarFact {
                    name: None,
                    ty: Some(o.fact(TypeId::from_index(9))),
                },
            ),
        ],
        plate: Some(o.fact("plate".to_string())),
    }
}

fn note(kind: NoteKind, members: Option<SetMembers>) -> Note {
    Note {
        id: NoteId(9),
        kind,
        text: "line one\nline \"two\"".to_string(),
        at: Some(Address::external(3)),
        func: Some(FuncId(ram(0x1080))),
        status: NoteStatus::Confirmed,
        tags: vec!["a".to_string(), "b".to_string()],
        evidence: vec!["fn:0x1080".to_string()],
        claims: vec![Claim {
            rel: "calls".to_string(),
            args: vec!["fn:0x1080".to_string(), "imp:puts".to_string()],
        }],
        set: members.map(|members| NoteSet {
            name: SetName::new("parsers").unwrap(),
            members,
        }),
        src: Source::User,
        session: session("cli"),
        rev: Rev(12),
    }
}

/// Gives edits of every variant, with each nested form at least once.
fn samples() -> Vec<Edit> {
    let o = agent();
    let key = RefKey {
        from: ram(0x1084),
        op_index: -1,
        to: Address::external(2),
        kind: RefType::ComputedCall,
    };
    let flows = [
        FlowOverride::Fallthrough(ram(0x1090)),
        FlowOverride::CallAsJump,
        FlowOverride::JumpAsCall,
        FlowOverride::IndirectTargets(vec![ram(0x1090), Address::external(1)]),
    ];
    let mut out = vec![
        Edit::SetName {
            addr: ram(0x1084),
            key: Some(SymKey(3)),
            kind: SymKind::GlobalVar,
            primary: false,
            name: Some(o.fact("ünïcode \u{1}".to_string())),
            evidence: vec!["fn:0x10c0".to_string(), "calls puts".to_string()],
        },
        Edit::SetName {
            addr: Address::external(1),
            key: None,
            kind: SymKind::Label,
            primary: true,
            name: None,
            evidence: Vec::new(),
        },
        Edit::SetComment {
            addr: ram(0x1088),
            kind: CommentKind::Repeatable,
            text: Some(o.fact("text".to_string())),
        },
        Edit::SetVarFact {
            var: var(Storage::Stack(-0x14)),
            field: VarField::Name(Some(o.fact("buf".to_string()))),
        },
        Edit::SetVarFact {
            var: var(Storage::Ret),
            field: VarField::Type(None),
        },
        Edit::AddRef {
            fact: o.fact(Ref { key, primary: true }),
        },
        Edit::RemoveRef { key },
        Edit::CreateFunction(Box::new(record())),
        Edit::DeleteFunction {
            id: FuncId(ram(0x1140)),
            cascade: true,
        },
        Edit::SetSignature {
            id: FuncId(ram(0x1080)),
            sig: Some(o.fact(TypeId::from_index(30))),
        },
        Edit::SetNoreturn {
            id: FuncId(ram(0x1080)),
            noreturn: None,
        },
        Edit::SetJumpTable {
            id: JumpTableId(ram(0x1140)),
            table: Some(o.fact(JumpTable {
                base: Some(ram(0x2000)),
                entry_size: 4,
                count: 3,
                targets: vec![ram(0x1150), ram(0x1160), ram(0x1150)],
                method: JtMethod::A,
                resolved: false,
            })),
        },
        Edit::SetDataDef {
            at: ram(0x4000),
            def: Some(o.fact(DataDef {
                ty: TypeId::from_index(9),
                len: 8,
            })),
        },
        Edit::WriteNote(Box::new(note(NoteKind::Hypothesis, None))),
        Edit::WriteNote(Box::new(note(
            NoteKind::Set,
            Some(SetMembers::Addrs(RangeSet::from_ranges(&[Range {
                first: 0x1080,
                last: 0x10ff,
            }]))),
        ))),
        Edit::WriteNote(Box::new(note(
            NoteKind::Set,
            Some(SetMembers::ids(vec!["fn:0x1080".to_string()])),
        ))),
        Edit::DeleteNote { id: NoteId(9) },
    ];
    for flow in flows {
        out.push(Edit::SetFlowOverride {
            at: ram(0x1090),
            flow: Some(o.fact(flow)),
        });
    }
    let p = seeded();
    out.push(Edit::ReplaceAnalysis(Box::new(p.analysis().clone())));
    out
}

fn reparse(v: &Value) -> Value {
    parse(&write(v), &Limits::DEFAULT).unwrap()
}

#[test]
fn edit_codec_roundtrip_every_variant() {
    let edits = samples();
    for kind in EditKind::ALL {
        assert!(
            edits.iter().any(|e| e.kind() == kind),
            "{kind} has a sample"
        );
    }
    for e in &edits {
        let v = edit_to_json(e);
        assert_eq!(v.get("op").and_then(Value::as_str), Some(e.kind().name()));
        let back = edit_from_json(&reparse(&v)).unwrap();
        assert_eq!(&back, e, "{}", e.kind());
        assert!(write_jcs(&v).is_ok());
    }
    let set = edit_to_json(&edits[0]);
    assert_eq!(
        set.pointer("/name/value").and_then(Value::as_str),
        Some("ünïcode \u{1}")
    );
    assert_eq!(set.pointer("/name/tx").and_then(Value::as_u64), Some(42));
    assert_eq!(set.pointer("/addr").and_then(Value::as_str), Some("0x1084"));
}

#[test]
fn key_codec_roundtrip_every_variant() {
    let keys = [
        FactKey::CodeUnit(0x10),
        FactKey::Data(0x11),
        FactKey::Symbol(ram(0x12), SymKey(2)),
        FactKey::Func(FuncId(ram(0x13))),
        FactKey::Signature(FuncId(ram(0x14))),
        FactKey::Noreturn(FuncId(ram(0x15))),
        FactKey::Ref(RefKey {
            from: ram(0x16),
            op_index: 1,
            to: ram(0x17),
            kind: RefType::Write,
        }),
        FactKey::Comment(ram(0x18), CommentKind::Post),
        FactKey::JumpTable(JumpTableId(ram(0x19))),
        FactKey::FlowOverride(ram(0x1a)),
        FactKey::Str(StringId(ram(0x1b))),
        FactKey::Var(var(Storage::Param(2))),
        FactKey::Import(ImportId::pe_by_ordinal("kernel32.dll", 7).unwrap()),
        FactKey::Export(ExportId::by_name("main").unwrap()),
        FactKey::Entry(0x1c),
        FactKey::Reloc(0x1d),
        FactKey::Fde(0x1e),
        FactKey::Note(NoteId(4)),
    ];
    for key in &keys {
        let v = key_to_json(key);
        assert_eq!(&key_from_json(&reparse(&v)).unwrap(), key, "{v}");
    }
    assert_eq!(
        key_to_json(&keys[2]).to_string(),
        r#"{"k":"symbol","addr":"0x12","key":2}"#
    );
}

#[test]
fn tables_notes_and_progress_roundtrip() {
    let mut p = seeded();
    let base = agent();
    let layer = p.layer_mut(Source::Agent).unwrap();
    let rec = record();
    layer.funcs.insert(rec.func).unwrap();
    for (id, facts) in rec.vars {
        if let Some(n) = facts.name {
            layer
                .vars
                .set_name(&id, Some(n.value.clone()), &n.origin())
                .unwrap();
        }
        if let Some(t) = facts.ty {
            layer
                .vars
                .set_type(&id, Some(t.value), &t.origin())
                .unwrap();
        }
    }
    layer
        .comments
        .set(
            ram(0x1080),
            CommentKind::Plate,
            Some("p".to_string()),
            &base,
        )
        .unwrap();
    layer
        .overrides
        .set(ram(0x1090), Some(FlowOverride::JumpAsCall), &base)
        .unwrap();
    layer
        .listing
        .set_data(
            0x4000,
            Some(DataDef {
                ty: TypeId::from_index(9),
                len: 8,
            }),
            &base,
        )
        .unwrap();
    for tables in [p.base(), p.analysis()] {
        let v = tables_to_json(tables);
        assert_eq!(&tables_from_json(&reparse(&v)).unwrap(), tables);
    }
    let notes = p.notes_mut();
    notes.write(note(NoteKind::Finding, None)).unwrap();
    let mut gone = note(NoteKind::Todo, None);
    gone.id = NoteId(20);
    notes.write(gone).unwrap();
    notes.delete(NoteId(20));
    let v = notes_to_json(p.notes());
    let back = notes_from_json(&reparse(&v)).unwrap();
    assert_eq!(&back, p.notes());
    assert_eq!(back.next_id(), NoteId(21));
    let progress = p.progress_mut();
    progress.set(
        FuncId(ram(0x1080)),
        FuncProgress {
            visited: true,
            named: false,
            typed: true,
            commented: false,
        },
    );
    progress.set_mark(
        session("mcp-1"),
        Mark {
            last_brief_rev: Rev(3),
        },
    );
    let v = progress_to_json(p.progress());
    assert_eq!(&progress_from_json(&reparse(&v)).unwrap(), p.progress());
}

#[test]
fn facts_dump_leaves_out_counters() {
    let p = seeded();
    let dump = facts(&p);
    let names: Vec<&str> = dump.as_object().unwrap().iter().map(|(k, _)| k).collect();
    assert_eq!(names, vec!["analysis", "base", "binary", "notes", "types"]);
    assert!(dump.pointer("/analysis/why_next").is_none());
    assert!(tables_to_json(p.analysis()).get("why_next").is_some());
    let sha: String = p.meta().sha256.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        dump.get("binary").and_then(Value::as_str),
        Some(sha.as_str())
    );
    assert_eq!(
        dump.get("types").and_then(Value::as_u64),
        u64::try_from(p.types().store().len()).ok()
    );
}

fn bad(text: &str) -> CodecError {
    let v = parse(text, &Limits::DEFAULT).unwrap();
    edit_from_json(&v).unwrap_err()
}

#[test]
fn decoders_refuse_bad_input() {
    let fact = r#"{"value":"x","source":"agent","tx":1,"session":"cli","force":false}"#;
    let cases: Vec<(String, &str, Reason)> = vec![
        ("[]".to_string(), "", Reason::Json(DecodeKind::Type { expected: "object", found: "array" })),
        (r#"{"op":"Nope"}"#.to_string(), "/op", Reason::Text("edit kind")),
        (r#"{"op":"DeleteNote"}"#.to_string(), "/id", Reason::Json(DecodeKind::Missing)),
        (r#"{"op":"DeleteNote","id":1,"x":2}"#.to_string(), "/x", Reason::Json(DecodeKind::Unknown)),
        (r#"{"op":"DeleteNote","id":-1}"#.to_string(), "/id", Reason::Json(DecodeKind::Range)),
        (
            format!(r#"{{"op":"SetComment","addr":"0xzz","kind":"eol","text":{fact}}}"#),
            "/addr",
            Reason::Text("address"),
        ),
        (
            format!(r#"{{"op":"SetComment","addr":"0x1","kind":"side","text":{fact}}}"#),
            "/kind",
            Reason::Text("comment kind"),
        ),
        (
            r#"{"op":"SetComment","addr":"0x1","kind":"eol","text":{"value":"x","source":"boss","tx":1,"session":"cli","force":false}}"#.to_string(),
            "/text/source",
            Reason::Text("source"),
        ),
        (
            r#"{"op":"SetComment","addr":"0x1","kind":"eol","text":{"value":"x","source":"agent","tx":1,"session":"a b","force":false}}"#.to_string(),
            "/text/session",
            Reason::Text("session label"),
        ),
        (
            r#"{"op":"SetVarFact","var":"fn:0x10","field":{"name":null}}"#.to_string(),
            "/var",
            Reason::Text("variable ID"),
        ),
        (
            r#"{"op":"SetFlowOverride","at":"0x1","flow":{"value":{"kind":"warp"},"source":"agent","tx":1,"session":"cli","force":false}}"#.to_string(),
            "/flow/value/kind",
            Reason::Text("flow override"),
        ),
        (
            r#"{"op":"ReplaceAnalysis","set":{"units":[{"at":"0x10","len":0,"flow":"seq","flags":0}]}}"#.to_string(),
            "/set/comments",
            Reason::Json(DecodeKind::Missing),
        ),
    ];
    for (text, path, reason) in cases {
        let e = bad(&text);
        assert_eq!((e.path.as_str(), &e.reason), (path, &reason), "{text}");
        assert!(!e.to_string().is_empty());
    }
    let empty = r#"{"comments":[],"data":[],"funcs":[],"jumptables":[],"overrides":[],"refs":[],"strings":[],"symbols":[],"units":[{"at":"0x10","len":0,"flow":"seq","flags":0}],"vars":[],"why":[],"why_next":0}"#;
    let e = tables_from_json(&parse(empty, &Limits::DEFAULT).unwrap()).unwrap_err();
    assert_eq!(e.path, "/units/0");
    assert!(matches!(e.reason, Reason::Invalid(_)));
    let fact_v = parse(fact, &Limits::DEFAULT).unwrap();
    let f: Fact<String> = origin(Source::Agent, 1, "cli").fact("x".to_string());
    assert_eq!(
        fact_v.get("value").and_then(Value::as_str),
        Some(f.value.as_str())
    );
    let _ = TxId(0);
}
