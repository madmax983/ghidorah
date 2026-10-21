//! `search`: the loader listings, names, strings, bytes, notes, sets, jump tables and the
//! page conservation of every list tool (AC-217, AC-135).

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{BinaryId, SectionId, SetName, SymId};
use ghidorah_db::{Edit, Note, NoteKind, NoteSet, NoteStatus, SessionLabel, SetMembers, Source};
use ghidorah_json::Value;
use ghidorah_testkit::elf::{ElfBuilder, Loc, Note as ElfNote, Section, Symbol};

use crate::support::{
    addr_of, all_items, call, call_value, code, data, demo, fixture, items, json, load_bytes,
    program, str_of, text_at, truth_fixtures,
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

/// Gives the ID of the loader symbol `s` with the name `name` in `search` (r3-surface-03):
///
/// 1. The `sym:` ID when the name has exactly the one address of `s`.
/// 2. Else the function ID at the address, else the address when it is not 0.
/// 3. Else the `imp:` ID of an undefined ELF symbol: its name, or its name before `@`.
///
/// A symbol with no such ID, for example a file symbol at 0, gives `None`.
fn symbol_id(p: &ghidorah_db::Program, s: &ghidorah_loader::Sym, name: &str) -> Option<String> {
    let addr = ghidorah_base::Address::ram(s.addr);
    if p.addrs_named(name) == [addr]
        && let Ok(id) = SymId::new(name)
    {
        return Some(id.to_string());
    }
    if p.func(ghidorah_base::FuncId(addr)).is_some() {
        return Some(ghidorah_base::FuncId(addr).to_string());
    }
    if s.addr != 0 {
        return Some(addr.to_string());
    }
    let undefined = s.shndx == 0
        && matches!(
            s.table,
            ghidorah_loader::SymTable::Symtab | ghidorah_loader::SymTable::Dynsym
        );
    let base = name.split('@').next().unwrap_or(name);
    [name, base]
        .into_iter()
        .filter_map(|n| ghidorah_base::ImportId::elf(n).ok())
        .find(|i| undefined && p.imports().contains_key(i))
        .map(|i| i.to_string())
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
            .map(|s| {
                let index = u16::try_from(s.index).expect("a small section index");
                let raw = s.name.as_str().expect("a UTF-8 section name");
                SectionId::new(index, raw)
                    .expect("a section ID")
                    .to_string()
            })
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
        let p = program(&session, &id);
        let mut symbols: Vec<String> = b
            .symbols
            .iter()
            .filter(|s| !s.name.is_empty())
            .filter_map(|s| symbol_id(p, s, &text(&s.name)))
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

/// The symbol names of [`hostile`]: a name that starts with a quote, a backslash, a terminal
/// escape with a bidi mark and a name above the 256 characters of a display name.
pub fn hostile_names() -> [String; 5] {
    [
        "main".to_owned(),
        "\"main\"".to_owned(),
        "back\\slash".to_owned(),
        "\x1b[2J\u{202e}evil".to_owned(),
        format!("long_{}", "x".repeat(303)),
    ]
}

/// The name of the two data symbols of [`hostile`]: a name with a bidi mark (U+202E).
pub const EVIL: &str = "evil\u{202e}x";

/// The name of the section of [`hostile`] with a soft hyphen (U+00AD).
pub const SOFT_SECTION: &str = ".x\u{ad}y";

/// The owner name of the ELF note of [`hostile`]: a name with a backslash.
pub const NOTE_NAME: &str = "a\\b";

/// Loads an ELF file with the names of [`hostile_names`], one `ret` function each, the
/// sections `"q` and [`SOFT_SECTION`], a note of the owner [`NOTE_NAME`] and two data symbols
/// [`EVIL`] in `"q`.
pub fn hostile(test: &str) -> ghidorah_tools::Session {
    let at = |off| Loc::section(".text", off);
    let mut b = ElfBuilder::exec()
        .section(Section::code(".text", &[0xc3; 8]))
        .section(Section::rodata("\"q", &[1, 2, 3, 4]))
        .section(Section::rodata(SOFT_SECTION, &[5, 6, 7, 8]))
        .note(ElfNote {
            section: ".note.test".to_owned(),
            name: NOTE_NAME.to_owned(),
            kind: 1,
            desc: vec![0; 4],
            align: 4,
        });
    for (name, off) in hostile_names().iter().zip(0u64..) {
        b = b.symbol(Symbol::func(name, at(off), 1));
    }
    for off in 0..2 {
        b = b.symbol(Symbol::object(EVIL, Loc::section("\"q", off), 1));
    }
    let (session, load) = load_bytes(test, &b.entry(Loc::symbol("main")).build(), "full");
    assert_eq!(code(&load), "", "{load}");
    session
}

/// Sends `id` through `addr_info`. Makes sure that rule `id` resolves it to `addr`, and gives
/// the data.
fn round_trip(session: &mut ghidorah_tools::Session, id: &str, addr: &str) -> Value {
    let args = Value::object([("target", Value::from(id))]);
    let envelope = call_value(session, "addr_info", args);
    assert_eq!(code(&envelope), "", "{id:?}: {envelope}");
    let d = data(&envelope).clone();
    assert_eq!(text_at(&d, "/resolved_from/rule"), "id", "{id:?}: {d}");
    assert_eq!(text_at(&d, "/addr"), addr, "{id:?}: {d}");
    d
}

/// Gives the `search` items of `kind` whose `id` does not resolve through `addr_info`: an
/// error, or an address other than the `addr` of the item. An `imp:` ID resolves to the
/// entry of its import, so only its code counts. An address ID outside the memory map
/// resolves, and `addr_info` gives `ADDRESS_UNMAPPED` for it.
fn dead_ids(session: &mut ghidorah_tools::Session, kind: &str) -> Vec<String> {
    let args = Value::object([("kind", Value::from(kind))]);
    let mut bad = Vec::new();
    for item in all_items(session, "search", &args, 7) {
        let (id, addr) = (str_of(&item, "id"), str_of(&item, "addr"));
        let args = Value::object([("target", Value::from(id.as_str()))]);
        let envelope = call_value(session, "addr_info", args);
        let failed = code(&envelope);
        let outside = failed == "ADDRESS_UNMAPPED" && id == addr;
        let moved = !addr.is_empty()
            && !id.starts_with("imp:")
            && failed.is_empty()
            && text_at(&envelope, "/data/addr") != addr;
        if (!failed.is_empty() && !outside) || moved {
            bad.push(format!(
                "{item} -> {failed} {}",
                text_at(&envelope, "/data/addr")
            ));
        }
    }
    bad
}

/// The IDs of `search`, `binary_survey` and `addr_info` parse back to their item. A name that
/// starts with a quote, holds an escaped character or is long keeps its exact text in the ID
/// (r2-surface-01, known-02).
///
/// Each `search` item of the kinds `symbol` and `name` has an ID that resolves to the item.
/// A name of two symbols, a file symbol, an undefined versioned import and a linker symbol
/// outside the memory map give no `NOT_FOUND` and no `AMBIGUOUS_NAME` (r3-surface-03).
#[test]
fn regress_emitted_ids_round_trip() {
    let mut session = hostile("regress_emitted_ids_round_trip");
    for kind in ["symbol", "name"] {
        let bad = dead_ids(&mut session, kind);
        assert!(bad.is_empty(), "{kind}: {bad:#?}");
    }
    let (mut gcc, _) = fixture("adversarial_names.gcc-O2");
    let bad = dead_ids(&mut gcc, "symbol");
    assert!(bad.is_empty(), "{bad:#?}");
    let listed = all_items(&mut gcc, "search", &json(r#"{"kind":"symbol"}"#), 50);
    let id_of = |text: &str| -> Vec<String> {
        listed
            .iter()
            .filter(|i| str_of(i, "text") == text)
            .map(|i| str_of(i, "id"))
            .collect()
    };
    assert_eq!(
        id_of("__libc_start_main@GLIBC_2.34"),
        ["imp:__libc_start_main"]
    );
    assert_eq!(id_of("_end"), ["0x4018"]);
    assert_eq!(
        id_of("crtstuff.c"),
        Vec::<String>::new(),
        "a file symbol has no ID"
    );

    let args = Value::object([("kind", Value::from("symbol"))]);
    let symbols = all_items(&mut session, "search", &args, 7);
    let evil: BTreeSet<String> = symbols
        .iter()
        .filter(|i| str_of(i, "text") == r"evil\u{202e}x")
        .map(|i| str_of(i, "id"))
        .collect();
    assert_eq!(evil.len(), 2, "two IDs for two symbols: {symbols:?}");
    let mut found = BTreeSet::new();
    for item in &symbols {
        let id = str_of(item, "id");
        let Ok(ghidorah_base::Id::Sym(sym)) = ghidorah_base::Id::parse(&id) else {
            continue;
        };
        let d = round_trip(&mut session, &id, &str_of(item, "addr"));
        if item.pointer("/extra/kind").and_then(Value::as_str) == Some("func") {
            assert_eq!(text_at(&d, "/symbol/name"), str_of(item, "text"), "{d}");
            found.insert(sym.as_str().to_owned());
        }
    }
    let want: BTreeSet<String> = hostile_names().into_iter().collect();
    assert_eq!(found, want, "{symbols:?}");

    let args = Value::object([("kind", Value::from("section"))]);
    let sections: Vec<Value> = all_items(&mut session, "search", &args, 7)
        .into_iter()
        .filter(|i| !str_of(i, "addr").is_empty())
        .collect();
    let survey = call(&mut session, "binary_survey", r#"{"include":["sections"]}"#);
    let listed = data(&survey)
        .pointer("/sections/items")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default();
    let mut ids = BTreeSet::new();
    for item in &sections {
        let (id, addr) = (str_of(item, "id"), str_of(item, "addr"));
        let d = round_trip(&mut session, &id, &addr);
        assert_eq!(text_at(&d, "/section/id"), id, "{item}: {d}");
        let at = call_value(
            &mut session,
            "addr_info",
            Value::object([("target", Value::from(addr.as_str()))]),
        );
        let from_info = text_at(data(&at), "/section/id");
        let d = round_trip(&mut session, &from_info, &addr);
        assert_eq!(text_at(&d, "/section/id"), id, "{at}");
        let row = listed
            .iter()
            .find(|s| str_of(s, "start") == addr)
            .unwrap_or_else(|| panic!("binary_survey lists {addr}: {survey}"));
        let d = round_trip(&mut session, &str_of(row, "id"), &addr);
        assert_eq!(text_at(&d, "/section/id"), id, "{row}");
        if let Ok(ghidorah_base::Id::Section(sec)) = ghidorah_base::Id::parse(&id) {
            ids.insert(sec.name().to_owned());
        }
    }
    for name in ["\"q", SOFT_SECTION, ".text"] {
        assert!(ids.contains(name), "{name:?} in {sections:?}");
    }
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

/// Checks that `paged` holds exactly `total` unique items in the order of `single`.
///
/// # Errors
///
/// Gives the first problem: a wrong count, a duplicate item or another order.
fn conserved(paged: &[Value], single: &[Value], total: u64) -> Result<(), String> {
    let count = u64::try_from(paged.len()).unwrap_or(u64::MAX);
    if count != total {
        return Err(format!("{count} paged items, total {total}"));
    }
    let unique: BTreeSet<String> = paged.iter().map(ghidorah_json::write).collect();
    if unique.len() != paged.len() {
        return Err("duplicate items".to_owned());
    }
    if total <= 1000 && paged != single {
        return Err("the pages change the order".to_owned());
    }
    Ok(())
}

/// Checks that the pages of 7 items of one list call give exactly `total` unique items in one
/// order. Gives the total.
fn conserve(session: &mut ghidorah_tools::Session, tool: &str, args: &Value, label: &str) -> u64 {
    conserve_by(session, tool, args, label, 7)
}

/// Checks that the pages of `page` items of one list call give exactly `total` unique items in
/// one order. Gives the total.
fn conserve_by(
    session: &mut ghidorah_tools::Session,
    tool: &str,
    args: &Value,
    label: &str,
    page: u32,
) -> u64 {
    let mut one = args.as_object().cloned().unwrap_or_default();
    one.push("limit", Value::from(1000));
    let single = call_value(session, tool, Value::Object(one));
    let total = single
        .pointer("/page/total")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{label}: {single}"));
    let paged = all_items(session, tool, args, page);
    if let Err(problem) = conserved(&paged, &items(&single), total) {
        panic!("{label}: {problem}");
    }
    assert!(
        tool != "func_list" || total > 0,
        "{label}: the fixture has functions"
    );
    total
}

/// Makes comments, renames, notes and sets on the open binary, so that `history_list` and
/// the note and set kinds of `search` have rows.
fn make_rows(session: &mut ghidorah_tools::Session) {
    let funcs = items(&call(session, "func_list", r#"{"limit":5}"#));
    let ids: Vec<String> = funcs.iter().map(|f| str_of(f, "id")).collect();
    assert!(ids.len() >= 3, "{funcs:?}");
    for (i, id) in ids.iter().enumerate() {
        let edits = [
            (
                "comment_set",
                Value::object([
                    ("target", Value::from(id.as_str())),
                    ("kind", Value::from("plate")),
                    ("text", Value::from(format!("First text {i}."))),
                ]),
            ),
            (
                "comment_set",
                Value::object([
                    ("target", Value::from(id.as_str())),
                    ("kind", Value::from("plate")),
                    ("text", Value::from(format!("Second text {i}."))),
                ]),
            ),
            (
                "symbol_rename",
                Value::object([
                    ("target", Value::from(id.as_str())),
                    ("name", Value::from(format!("paged_{i}"))),
                    ("force", Value::Bool(true)),
                ]),
            ),
            (
                "note_write",
                Value::object([
                    ("kind", Value::from("note")),
                    ("text", Value::from(format!("Note {i}."))),
                    ("at", Value::from(id.as_str())),
                ]),
            ),
        ];
        for (tool, args) in edits {
            let envelope = call_value(session, tool, args);
            assert_eq!(text_at(&envelope, "/error/code"), "", "{tool}: {envelope}");
        }
    }
    for (name, members) in [("first", &ids[..2]), ("second", &ids[1..])] {
        let members = members.iter().map(|m| Value::from(m.as_str())).collect();
        let set = Value::object([
            ("name", Value::from(name)),
            ("members", Value::Array(members)),
            ("op", Value::from("union")),
        ]);
        let args = Value::object([("kind", Value::from("set")), ("set", set)]);
        let envelope = call_value(session, "note_write", args);
        assert_eq!(text_at(&envelope, "/error/code"), "", "{envelope}");
    }
}

#[test]
fn ac_135_pagination_conservation() {
    let mut checked = 0;
    let mut xrefs = 0;
    let mut with_items: BTreeMap<&str, usize> = BTreeMap::new();
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
        for kind in [
            "name",
            "string",
            "import",
            "section",
            "symbol",
            "segment",
            "library",
            "export",
            "jumptable",
        ] {
            let args = Value::object([("kind", Value::from(kind))]);
            let total = conserve(&mut session, "search", &args, &format!("{name} {kind}"));
            *with_items.entry(kind).or_default() += usize::from(total > 0);
        }
        let args = json(r#"{"targets":["main","_start"],"direction":"from"}"#);
        let ok = call_value(&mut session, "xref_list", args.clone());
        if ok.get("ok") == Some(&Value::Bool(true)) {
            conserve(&mut session, "xref_list", &args, &format!("{name} xrefs"));
            xrefs += 1;
        }
        checked += 1;
    }
    assert!(checked >= 60);
    assert!(
        xrefs >= 60,
        "xref_list pages on {xrefs} of {checked} fixtures"
    );
    for (kind, count) in &with_items {
        assert!(*count > 0, "no fixture has search items of the kind {kind}");
    }

    // history_list, the note and set kinds of search, and tool_search.
    let (mut session, _) = fixture("hello.gcc-O2");
    make_rows(&mut session);
    let coalesced = conserve(
        &mut session,
        "history_list",
        &json(r#"{"since_rev":0}"#),
        "history",
    );
    let raw = conserve(
        &mut session,
        "history_list",
        &json(r#"{"since_rev":0,"coalesce":false}"#),
        "history raw",
    );
    assert!(coalesced >= 10, "{coalesced} coalesced rows");
    assert!(
        raw > coalesced,
        "{raw} raw rows, {coalesced} coalesced rows"
    );
    for kind in ["note", "set"] {
        let args = Value::object([("kind", Value::from(kind))]);
        let total = conserve(&mut session, "search", &args, kind);
        assert!(total >= 2, "{kind}: {total} items");
    }
    for args in [
        r#"{"query":"function"}"#,
        r#"{"query":"list","level":"names"}"#,
    ] {
        let total = conserve_by(&mut session, "tool_search", &json(args), args, 2);
        assert!(
            total >= 3,
            "{args}: {total} items, so the pages are at least 2"
        );
    }

    // A negative control: a page sequence that repeats or drops an item fails the check.
    let single = all_items(&mut session, "func_list", &json("{}"), 1000);
    assert!(single.len() >= 3);
    let total = u64::try_from(single.len()).expect("a count");
    assert_eq!(conserved(&single, &single, total), Ok(()));
    let mut repeated = single.clone();
    repeated[1] = repeated[0].clone();
    assert!(conserved(&repeated, &single, total).is_err());
    let mut dropped = single.clone();
    dropped.remove(1);
    assert!(conserved(&dropped, &single, total).is_err());
    let mut swapped = single.clone();
    swapped.swap(0, 1);
    assert!(conserved(&swapped, &single, total).is_err());
    let _ = data;
}
