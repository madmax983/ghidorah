//! `search`: the loader listings, names, strings, bytes, notes, sets, jump tables and the
//! page conservation of every list tool (AC-217, AC-135).

use std::collections::BTreeSet;

use ghidorah_base::{BinaryId, SetName};
use ghidorah_db::{Edit, Note, NoteKind, NoteSet, NoteStatus, SessionLabel, SetMembers, Source};
use ghidorah_json::Value;

use crate::support::{
    addr_of, all_items, call, call_value, data, demo, fixture, items, json, program, str_of,
    text_at, truth_fixtures,
};

/// Gives the sorted `(id, text)` pairs of every item of `search { kind }`.
fn listing(session: &mut ghidorah_tools::Session, kind: &str) -> Vec<String> {
    let args = Value::object([("kind", Value::from(kind))]);
    let mut out: Vec<String> = all_items(session, "search", &args, 7)
        .iter()
        .map(|i| str_of(i, "id"))
        .collect();
    out.sort();
    out
}

#[test]
fn ac_217_search_listing() {
    for name in [
        "hello.gcc-O2",
        "hello.gcc-O2.noshdr",
        "socket_client.gcc-O2",
        "adversarial_names.gcc-O2",
        "switch.gcc-O2-at400000",
    ] {
        let (mut session, id) = fixture(name);
        let b = program(&session, &id).binary().clone();
        let text = |t: &ghidorah_base::BinText| t.render(ghidorah_base::Caps::DETAILED).text;
        let mut imports: Vec<String> = program(&session, &id)
            .imports()
            .keys()
            .map(ToString::to_string)
            .collect();
        imports.sort();
        assert_eq!(listing(&mut session, "import"), imports, "{name} imports");
        let mut exports: Vec<String> = program(&session, &id)
            .exports()
            .keys()
            .map(ToString::to_string)
            .collect();
        exports.sort();
        assert_eq!(listing(&mut session, "export"), exports, "{name} exports");
        let mut sections: Vec<String> = b
            .sections
            .iter()
            .map(|s| format!("sec:{}:{}", s.index, text(&s.name)))
            .collect();
        sections.sort();
        assert_eq!(
            listing(&mut session, "section"),
            sections,
            "{name} sections"
        );
        let mut segments: Vec<String> = b
            .segments
            .iter()
            .map(|s| format!("seg:{}", s.index))
            .collect();
        segments.sort();
        assert_eq!(
            listing(&mut session, "segment"),
            segments,
            "{name} segments"
        );
        let args = Value::object([("kind", Value::from("library"))]);
        let mut libraries: Vec<String> = all_items(&mut session, "search", &args, 7)
            .iter()
            .map(|i| str_of(i, "text"))
            .collect();
        libraries.sort();
        let mut want: Vec<String> = b.libraries.iter().map(text).collect();
        want.sort();
        assert_eq!(libraries, want, "{name} libraries");
        let mut symbols: Vec<String> = b
            .symbols
            .iter()
            .filter(|s| !s.name.is_empty())
            .map(|s| format!("sym:{}", text(&s.name)))
            .collect();
        symbols.sort();
        assert_eq!(listing(&mut session, "symbol"), symbols, "{name} symbols");
    }
}

#[test]
fn search_names_strings_and_bytes() {
    let mut session = demo();
    let names = items(&call(
        &mut session,
        "search",
        r#"{"kind":"name","query":"PASS"}"#,
    ));
    assert!(
        names
            .iter()
            .any(|i| str_of(i, "kind") == "function" && str_of(i, "id") == "fn:0x11e0"),
        "{names:?}"
    );
    let glob = items(&call(
        &mut session,
        "search",
        r#"{"kind":"name","query":"check_*","match":"glob"}"#,
    ));
    assert!(!glob.is_empty());
    let exact = items(&call(
        &mut session,
        "search",
        r#"{"kind":"name","query":"check","match":"exact"}"#,
    ));
    assert!(exact.is_empty(), "{exact:?}");
    let strings = items(&call(
        &mut session,
        "search",
        r#"{"kind":"string","query":"access"}"#,
    ));
    assert_eq!(strings.len(), 2, "{strings:?}");
    for s in &strings {
        assert!(crate::support::is_bin_text(s.get("text").expect("text")));
        assert!(
            s.pointer("/extra/ref_count")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                >= 1
        );
        assert_eq!(text_at(s, "/next/tool"), "xref_list");
        assert_eq!(
            s.pointer("/next/args/targets/0").and_then(Value::as_str),
            Some(str_of(s, "id").as_str())
        );
    }
    let hits = items(&call(
        &mut session,
        "search",
        r#"{"kind":"bytes","pattern":"e8 ?? ?? ?? ??"}"#,
    ));
    assert!(
        hits.iter().any(|h| str_of(h, "addr") == "0x1091"),
        "{hits:?}"
    );
    let p = program(&session, crate::support::DEMO_ID);
    for hit in &hits {
        let at = addr_of(&str_of(hit, "addr"));
        let byte = p
            .mem()
            .read(at, 1, &ghidorah_base::Limits::DEFAULT)
            .expect("a byte");
        assert_eq!(byte.first().copied(), Some(0xe8));
    }
    let nibble = items(&call(
        &mut session,
        "search",
        r#"{"kind":"bytes","pattern":"f3 0f 1e f?","scope":{"perms":"x"}}"#,
    ));
    assert!(
        nibble.iter().any(|h| str_of(h, "addr") == "0x1080"),
        "{nibble:?}"
    );
    let bad = call(&mut session, "search", r#"{"kind":"bytes","pattern":"zz"}"#);
    assert_eq!(crate::support::code(&bad), "INVALID_ARGUMENT", "{bad}");
    let types = items(&call(
        &mut session,
        "search",
        r#"{"kind":"type","query":"sockaddr"}"#,
    ));
    assert!(
        types.iter().any(|t| str_of(t, "id") == "t:sockaddr_in"),
        "{types:?}"
    );
    let scoped = items(&call(
        &mut session,
        "search",
        r#"{"kind":"name","scope":{"func":"main"}}"#,
    ));
    assert!(
        scoped.iter().all(|i| str_of(i, "addr").starts_with("0x10")),
        "{scoped:?}"
    );
}

/// A query matches the decoded text of a UTF-16 string, not its raw bytes (found by WP-26).
#[test]
fn regress_search_utf16_string() {
    let (mut session, _) = fixture("strings.gcc-O2");
    let hits = items(&call(
        &mut session,
        "search",
        r#"{"kind":"string","query":"Wide hello from UTF-16"}"#,
    ));
    let ids: Vec<String> = hits.iter().map(|h| str_of(h, "id")).collect();
    assert_eq!(ids, ["str:0x2060"], "{hits:?}");
}

/// Writes one note to the demo session and gives its ID.
fn write_note(session: &mut ghidorah_tools::Session, kind: NoteKind, set: Option<NoteSet>) -> u64 {
    let id = BinaryId::parse(crate::support::DEMO_ID).expect("an ID");
    let binary = session.binary_mut(id).expect("the demo is open");
    let next = binary.program.notes().next_id();
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = binary
        .program
        .begin("note_write", Source::Agent, label.clone())
        .expect("a transaction");
    let note = Note {
        id: next,
        kind,
        text: "check the key loop".to_owned(),
        at: Some(ghidorah_base::Address::ram(0x11e0)),
        func: Some(ghidorah_base::FuncId(ghidorah_base::Address::ram(0x11e0))),
        status: NoteStatus::Open,
        tags: vec!["crypto".to_owned()],
        evidence: Vec::new(),
        lift_ver: None,
        claims: Vec::new(),
        set,
        src: Source::Agent,
        session: label,
        rev: tx.pending_rev(),
    };
    tx.apply(Edit::WriteNote(Box::new(note)))
        .expect("the note applies");
    tx.commit().expect("the commit works");
    next.0
}

#[test]
fn search_notes_sets_and_ids() {
    let mut session = demo();
    let todo = write_note(&mut session, NoteKind::Todo, None);
    let members = SetMembers::ids(vec!["fn:0x1080".to_owned(), "fn:0x11e0".to_owned()]);
    let set = NoteSet {
        name: SetName::new("checks").expect("a set name"),
        members,
    };
    let _ = write_note(&mut session, NoteKind::Set, Some(set));
    let notes = items(&call(
        &mut session,
        "search",
        r#"{"kind":"note","note_filter":{"kind":"todo"}}"#,
    ));
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(str_of(&notes[0], "id"), format!("note:{todo}"));
    let sets = items(&call(&mut session, "search", r#"{"kind":"set"}"#));
    assert_eq!(sets.len(), 1);
    assert_eq!(str_of(&sets[0], "id"), "set:checks");
    let args = Value::object([(
        "ids",
        Value::Array(vec![
            Value::from(format!("note:{todo}")),
            Value::from("set:checks"),
        ]),
    )]);
    let records = items(&call_value(&mut session, "search", args));
    let kinds: Vec<String> = records.iter().map(|r| str_of(r, "kind")).collect();
    assert_eq!(kinds, ["note", "set", "set", "set"], "{records:?}");
    assert_eq!(
        records[0].pointer("/extra/status").and_then(Value::as_str),
        Some("open")
    );
    let members: BTreeSet<String> = records[2..]
        .iter()
        .filter_map(|r| r.pointer("/extra/member").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    assert_eq!(members.len(), 2, "{records:?}");
    let in_set = items(&call(&mut session, "func_list", r#"{"in":"set:checks"}"#));
    assert_eq!(in_set.len(), 2);
    let missing = call(&mut session, "search", r#"{"ids":["note:99"]}"#);
    assert_eq!(crate::support::code(&missing), "NOT_FOUND", "{missing}");
}

#[test]
fn search_jumptables() {
    let (mut session, _) = fixture("switch.gcc-O2");
    let tables = items(&call(&mut session, "search", r#"{"kind":"jumptable"}"#));
    let resolved = tables
        .iter()
        .find(|t| t.pointer("/extra/resolved") == Some(&Value::Bool(true)))
        .expect("the switch fixture has a resolved jump table");
    let first = str_of(resolved, "id");
    assert!(first.starts_with("jt:"));
    let args = Value::object([("ids", Value::Array(vec![Value::from(first.as_str())]))]);
    let records = items(&call_value(&mut session, "search", args));
    assert_eq!(records.len(), 1);
    let targets = records[0]
        .pointer("/extra/targets")
        .and_then(Value::as_array)
        .expect("targets");
    assert!(targets.len() >= 2, "{records:?}");
}

/// Checks that the pages of one list call give exactly `total` unique items in one order.
fn conserve(session: &mut ghidorah_tools::Session, tool: &str, args: &Value, label: &str) {
    let mut one = args.as_object().cloned().unwrap_or_default();
    one.push("limit", Value::from(1000));
    let single = call_value(session, tool, Value::Object(one));
    let total = single
        .pointer("/page/total")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{label}: {single}"));
    let paged = all_items(session, tool, args, 7);
    assert_eq!(
        u64::try_from(paged.len()).expect("a count"),
        total,
        "{label}"
    );
    assert!(
        tool != "func_list" || total > 0,
        "{label}: the fixture has functions"
    );
    let unique: BTreeSet<String> = paged.iter().map(ghidorah_json::write).collect();
    assert_eq!(unique.len(), paged.len(), "{label}: duplicate items");
    if total <= 1000 {
        assert_eq!(paged, items(&single), "{label}: one order");
    }
}

#[test]
fn ac_135_pagination_conservation() {
    let mut checked = 0;
    for name in truth_fixtures() {
        let (mut session, _) = fixture(name);
        conserve(&mut session, "func_list", &json("{}"), name);
        conserve(
            &mut session,
            "func_list",
            &json(r#"{"sort":"priority"}"#),
            name,
        );
        conserve(&mut session, "func_list", &json(r#"{"sort":"name"}"#), name);
        for kind in ["name", "string", "import", "section", "symbol", "segment"] {
            let args = Value::object([("kind", Value::from(kind))]);
            conserve(&mut session, "search", &args, &format!("{name} {kind}"));
        }
        let args = json(r#"{"targets":["main","_start"],"direction":"from"}"#);
        let ok = call_value(&mut session, "xref_list", args.clone());
        if ok.get("ok") == Some(&Value::Bool(true)) {
            conserve(&mut session, "xref_list", &args, &format!("{name} xrefs"));
        }
        checked += 1;
    }
    assert!(checked >= 60);
    let _ = data;
}
