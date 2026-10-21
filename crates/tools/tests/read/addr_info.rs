//! `addr_info` and the per-item results of list inputs (AC-144).

use ghidorah_json::Value;
use ghidorah_testkit::elf::{ElfBuilder, Loc, Section, Symbol};
use ghidorah_testkit::pe::{Dll, ExportItem, Exports, PeBuilder, Section as PeSection, Thunk};

use crate::support::{
    all_items, call, call_value, code, data, demo, fixture, items, json, load_bytes, str_of,
    text_at,
};

#[test]
fn addr_info_fields() {
    let mut session = demo();
    let main = call(&mut session, "addr_info", r#"{"target":"main"}"#);
    let d = data(&main);
    assert_eq!(text_at(d, "/addr"), "0x1080");
    assert_eq!(text_at(d, "/resolved_from/rule"), "symbol");
    assert_eq!(text_at(d, "/resolved_from/matched"), "main");
    assert_eq!(text_at(d, "/func/id"), "fn:0x1080");
    assert_eq!(text_at(d, "/func/name"), "main");
    assert_eq!(text_at(d, "/func/offset"), "0x0");
    assert_eq!(text_at(d, "/section/name"), ".text");
    assert_eq!(text_at(d, "/region/perms"), "r-x");
    assert_eq!(text_at(d, "/code_unit/kind"), "insn");
    assert_eq!(text_at(d, "/code_unit/mnem"), "endbr64");
    assert_eq!(text_at(d, "/symbol/name"), "main");
    assert_eq!(text_at(d, "/file_offset"), "0x1080");
    assert!(d.get("xrefs_in").and_then(Value::as_u64).unwrap_or(0) >= 1);
    let site = call(&mut session, "addr_info", r#"{"target":"0x1091"}"#);
    let d = data(&site);
    assert_eq!(text_at(d, "/func/offset"), "0x11");
    assert_eq!(text_at(d, "/code_unit/mnem"), "call");
    assert_eq!(d.get("xrefs_out").and_then(Value::as_u64), Some(1));
    let text = call(&mut session, "addr_info", r#"{"target":"str:0x201e"}"#);
    let d = data(&text);
    assert_eq!(text_at(d, "/section/name"), ".rodata");
    assert!(d.get("func").is_none());
    assert!(d.get("xrefs_in").and_then(Value::as_u64).unwrap_or(0) >= 1);
    let import = call(
        &mut session,
        "addr_info",
        r#"{"target":"imp:puts","include":["refs","comments"]}"#,
    );
    let d = data(&import);
    assert_eq!(text_at(d, "/addr"), "0x1060");
    let refs_in = d
        .pointer("/refs/in")
        .and_then(Value::as_array)
        .expect("refs in");
    assert_eq!(refs_in.len(), 3, "{import}");
    assert!(d.get("comments").and_then(Value::as_array).is_some());
}

#[test]
fn ac_144_per_item_results() {
    let mut session = demo();
    let got = call(
        &mut session,
        "func_get",
        r#"{"targets":["main","no_such_function","0x11e0"]}"#,
    );
    assert_eq!(got.get("ok"), Some(&Value::Bool(true)), "{got}");
    let list = items(&got);
    let inputs: Vec<String> = list.iter().map(|i| str_of(i, "input")).collect();
    assert_eq!(inputs, ["main", "no_such_function", "0x11e0"]);
    let oks: Vec<bool> = list
        .iter()
        .map(|i| i.get("ok") == Some(&Value::Bool(true)))
        .collect();
    assert_eq!(oks, [true, false, true]);
    assert_eq!(text_at(&list[0], "/data/id"), "fn:0x1080");
    assert_eq!(text_at(&list[1], "/error/code"), "NOT_FOUND");
    assert_eq!(text_at(&list[2], "/data/id"), "fn:0x11e0");
    let d = data(&got);
    assert_eq!(d.get("ok_count").and_then(Value::as_u64), Some(2));
    assert_eq!(d.get("error_count").and_then(Value::as_u64), Some(1));

    let info = call(
        &mut session,
        "addr_info",
        r#"{"targets":["0x99999999","imp:puts",4096]}"#,
    );
    assert_eq!(info.get("ok"), Some(&Value::Bool(true)), "{info}");
    let list = items(&info);
    assert_eq!(list.len(), 3);
    assert_eq!(text_at(&list[0], "/error/code"), "ADDRESS_UNMAPPED");
    assert_eq!(text_at(&list[1], "/data/addr"), "0x1060");
    assert_eq!(text_at(&list[2], "/data/addr"), "0x1000");
    assert_eq!(list[2].get("input"), Some(&Value::from(4096)));
    assert_eq!(
        text_at(&list[0], "/error/field_path"),
        "/targets/0",
        "the error names the item"
    );
}

/// A hex text with a letter and no `0x` gets a repair call with the prefix (found by WP-26).
#[test]
fn regress_bare_hex_has_repair_call() {
    let mut session = demo();
    for tool in ["func_get", "addr_info", "mem_read"] {
        let bad = call(&mut session, tool, r#"{"target":"11e0"}"#);
        assert_eq!(code(&bad), "ADDRESS_INVALID", "{bad}");
        assert_eq!(text_at(&bad, "/next/0/tool"), tool, "{bad}");
        assert_eq!(text_at(&bad, "/next/0/args/target"), "0x11e0", "{bad}");
        let args = bad.pointer("/next/0/args").cloned().unwrap_or(Value::Null);
        let fixed = call_value(&mut session, tool, args);
        assert_eq!(code(&fixed), "", "{fixed}");
    }
}

/// Gives the `ok` flags of the items of a per-item result.
fn oks(envelope: &Value) -> Vec<bool> {
    items(envelope)
        .iter()
        .map(|i| i.get("ok") == Some(&Value::Bool(true)))
        .collect()
}

/// A list item with bad address syntax fails only that item (AC-144, agent-protocol-05). An
/// ID prefix with a bad body gives `INVALID_ARGUMENT` that names the ID kind.
#[test]
fn regress_list_item_syntax_error_is_per_item() {
    let (mut session, _) = fixture("func_ptrs.gcc-O2");
    let got = call(
        &mut session,
        "func_get",
        r#"{"targets":["main","nosuch","fn:zz","0xzz"]}"#,
    );
    assert_eq!(code(&got), "", "{got}");
    assert_eq!(oks(&got), [true, false, false, false], "{got}");
    let list = items(&got);
    assert_eq!(text_at(&list[0], "/data/name"), "main", "{got}");
    assert_eq!(text_at(&list[1], "/error/code"), "NOT_FOUND");
    assert_eq!(
        text_at(&list[2], "/error/code"),
        "INVALID_ARGUMENT",
        "{got}"
    );
    assert_eq!(text_at(&list[2], "/error/field_path"), "/targets/2");
    let expected = text_at(&list[2], "/error/details/expected");
    assert!(
        expected.contains("fn:"),
        "the error names the ID kind: {got}"
    );
    assert!(
        !text_at(&list[2], "/error/message").contains("0x hex string"),
        "{got}"
    );
    assert_eq!(text_at(&list[3], "/error/code"), "ADDRESS_INVALID", "{got}");
    assert_eq!(text_at(&list[3], "/error/field_path"), "/targets/3");

    let one = call(&mut session, "func_get", r#"{"target":"fn:zz"}"#);
    assert_eq!(
        code(&one),
        "INVALID_ARGUMENT",
        "a single target fails the call: {one}"
    );
    assert_eq!(text_at(&one, "/error/field_path"), "/target");
    assert!(
        text_at(&one, "/error/details/expected").contains("fn:"),
        "{one}"
    );

    let renamed = call(
        &mut session,
        "symbol_rename",
        r#"{"items":[{"target":"0x1366","name":"op_jump"},{"target":"fn:qq","name":"bad"}]}"#,
    );
    assert_eq!(code(&renamed), "", "{renamed}");
    assert_eq!(oks(&renamed), [true, false], "{renamed}");
    let list = items(&renamed);
    assert_eq!(text_at(&list[1], "/error/code"), "INVALID_ARGUMENT");
    assert_eq!(text_at(&list[1], "/error/field_path"), "/items/1/target");

    let refs = call(
        &mut session,
        "xref_list",
        r#"{"targets":["fn:0x1350","fn:zz"],"direction":"from"}"#,
    );
    assert_eq!(code(&refs), "", "{refs}");
    assert!(!items(&refs).is_empty(), "{refs}");
    let errors = data(&refs)
        .get("errors")
        .and_then(Value::as_array)
        .expect("errors");
    assert_eq!(errors.len(), 1, "{refs}");
    assert_eq!(errors[0].get("index").and_then(Value::as_u64), Some(1));
    assert_eq!(
        errors[0].pointer("/error/code").and_then(Value::as_str),
        Some("INVALID_ARGUMENT")
    );
}

/// A section name escapes once. The soft hyphen (U+00AD) of `.x<U+00AD>y` shows as `\u{ad}`
/// with one backslash in `search`, `addr_info` and `binary_survey` (r2-surface-05). The note
/// owner name of `binary_survey` escapes once too.
#[test]
fn regress_section_name_escaped_once() {
    let mut session = crate::search::hostile("regress_section_name_escaped_once");
    let want = r".x\u{ad}y";
    let listed = all_items(&mut session, "search", &json(r#"{"kind":"section"}"#), 50);
    let hit = listed
        .iter()
        .find(|i| str_of(i, "text") == want)
        .unwrap_or_else(|| panic!("search shows {want}: {listed:?}"));
    let addr = str_of(hit, "addr");
    let args = Value::object([("target", Value::from(addr.as_str()))]);
    let info = call_value(&mut session, "addr_info", args);
    assert_eq!(text_at(data(&info), "/section/name"), want, "{info}");
    let survey = call(
        &mut session,
        "binary_survey",
        r#"{"include":["sections","notes"]}"#,
    );
    let rows = data(&survey)
        .pointer("/sections/items")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default();
    let row = rows
        .iter()
        .find(|s| str_of(s, "start") == addr)
        .unwrap_or_else(|| panic!("binary_survey lists {addr}: {survey}"));
    assert_eq!(str_of(row, "name"), want, "{survey}");
    let notes = data(&survey)
        .pointer("/notes/items")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default();
    let names: Vec<String> = notes.iter().map(|n| str_of(n, "name")).collect();
    assert!(names.iter().any(|n| n == r"a\\b"), "{survey}");
}

/// Writes `with` over each copy of `marker` in `bytes`, and gives the number of copies.
fn patch(bytes: &mut [u8], marker: &[u8], with: &[u8]) -> usize {
    let mut count = 0;
    let mut at = 0;
    while let Some(off) = bytes
        .get(at..)
        .and_then(|rest| rest.windows(marker.len()).position(|w| w == marker))
    {
        let start = at + off;
        bytes[start..start + with.len()].copy_from_slice(with);
        count += 1;
        at = start + marker.len();
    }
    count
}

/// Gives the `text` of each `search` item of `kind` whose `text` starts with `head`.
fn texts(session: &mut ghidorah_tools::Session, kind: &str, head: &str) -> Vec<String> {
    let args = Value::object([("kind", Value::from(kind))]);
    all_items(session, "search", &args, 50)
        .iter()
        .map(|i| str_of(i, "text"))
        .filter(|t| t.starts_with(head))
        .collect()
}

/// A binary name that is not UTF-8 escapes once, the same as a section name (r3-surface-08,
/// k3-04). The symbol bytes `6e ff fe 78` show as `n\xff\xfex` in `search` kinds `symbol`
/// and `name` and in `addr_info`. The section bytes `73 ff fe 63` show as `s\xff\xfec`. An
/// ELF library, a PE library, a PE import library and a PE export forwarder escape once too.
/// The IDs still parse back.
#[test]
fn regress_binary_names_escaped_once() {
    let b = ElfBuilder::exec()
        .section(Section::code(".text", &[0xc3; 4]))
        .section(Section::rodata("sQQc", &[1, 2, 3, 4]))
        .symbol(Symbol::func("main", Loc::section(".text", 0), 1))
        .symbol(Symbol::func("nQQx", Loc::section(".text", 1), 1))
        .needed("lQQb.so")
        .entry(Loc::symbol("main"));
    let mut bytes = b.build();
    for (marker, with) in [
        (&b"nQQx"[..], &b"n\xff\xfex"[..]),
        (b"sQQc", b"s\xff\xfec"),
        (b"lQQb", b"l\xff\xfeb"),
    ] {
        assert!(patch(&mut bytes, marker, with) > 0, "{marker:?}");
    }
    let (mut s, load) = load_bytes("names_escaped_once", &bytes, "full");
    assert_eq!(code(&load), "", "{load}");
    assert_eq!(texts(&mut s, "section", "s"), [r"s\xff\xfec"]);
    assert_eq!(texts(&mut s, "library", "l"), [r"l\xff\xfeb.so"]);
    let want = r"n\xff\xfex";
    assert_eq!(texts(&mut s, "symbol", "n"), [want]);
    let named = all_items(
        &mut s,
        "search",
        &json(r#"{"kind":"name","query":"xfex"}"#),
        50,
    );
    let shown: Vec<String> = named.iter().map(|i| str_of(i, "text")).collect();
    assert_eq!(shown, [want], "{named:?}");
    let listed = all_items(&mut s, "search", &json(r#"{"kind":"symbol"}"#), 50);
    for item in listed.iter().chain(&named) {
        let args = Value::object([("target", Value::from(str_of(item, "id")))]);
        let info = call_value(&mut s, "addr_info", args);
        assert_eq!(code(&info), "", "{item}: {info}");
        assert_eq!(
            text_at(data(&info), "/addr"),
            str_of(item, "addr"),
            "{info}"
        );
        if str_of(item, "text") == want {
            assert_eq!(text_at(data(&info), "/symbol/name"), want, "{info}");
        }
    }

    let pe = PeBuilder::dll()
        .section(PeSection::code(".text", 0x1000, &[0xc3; 0x40]))
        .section(PeSection::data(".data", 0x2000, &[0x11; 0x40]))
        .import(Dll::new("dQQ.dll", vec![Thunk::name("Beep", 1)]))
        .exports(Exports {
            dll: "t.dll".to_owned(),
            base: 1,
            items: vec![
                ExportItem::Code(0x1000),
                ExportItem::Forward("fQQ.Fn".to_owned()),
            ],
            names: vec![("run".to_owned(), 0), ("fwd".to_owned(), 1)],
            number_of_names: None,
            number_of_functions: None,
        });
    let mut bytes = pe.build();
    for (marker, with) in [(&b"dQQ"[..], &b"d\xff\xfe"[..]), (b"fQQ", b"f\xff\xfe")] {
        assert!(patch(&mut bytes, marker, with) > 0, "{marker:?}");
    }
    let (mut s, load) = load_bytes("names_escaped_once_pe", &bytes, "full");
    assert_eq!(code(&load), "", "{load}");
    assert_eq!(texts(&mut s, "library", "d"), [r"d\xff\xfe.dll"]);
    let imports = all_items(&mut s, "search", &json(r#"{"kind":"import"}"#), 50);
    let libs: Vec<String> = imports.iter().map(|i| text_at(i, "/extra/lib")).collect();
    assert_eq!(libs, [r"d\xff\xfe.dll"], "{imports:?}");
    let exports = all_items(&mut s, "search", &json(r#"{"kind":"export"}"#), 50);
    let forwarders: Vec<String> = exports
        .iter()
        .map(|i| text_at(i, "/extra/forwarder"))
        .filter(|f| !f.is_empty())
        .collect();
    assert_eq!(forwarders, [r"f\xff\xfe.Fn"], "{exports:?}");
}
