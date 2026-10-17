//! `addr_info` and the per-item results of list inputs (AC-144).

use ghidorah_json::Value;

use crate::support::{call, data, demo, items, str_of, text_at};

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
