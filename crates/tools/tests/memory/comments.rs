//! `comment_set`: set, change, delete and read back comments, and item lists.

use ghidorah_json::Value;

use crate::support::{STRIPPED, call, code, data, fixture, int_at, items, str_of, text_at};

#[test]
fn comment_set_and_read_back() {
    let (mut session, _) = fixture(STRIPPED);
    let first = call(
        &mut session,
        "comment_set",
        r#"{"target":"main+0x4","kind":"eol","text":"Make room on the stack."}"#,
    );
    let item = items(&first).first().cloned().expect("one item");
    assert_eq!(str_of(&item, "addr"), "0x1084", "{first}");
    assert_eq!(str_of(&item, "kind"), "eol");
    assert_eq!(item.get("old"), Some(&Value::Null));
    assert_eq!(str_of(&item, "new"), "Make room on the stack.");
    assert_eq!(item.get("noop"), Some(&Value::Bool(false)));
    let rev = int_at(&first, "/rev");

    let info = call(
        &mut session,
        "addr_info",
        r#"{"target":"0x1084","include":["comments"]}"#,
    );
    let shown = ghidorah_json::write(data(&info));
    assert!(shown.contains("Make room on the stack."), "{info}");
    let rows = call(
        &mut session,
        "func_get",
        r#"{"target":"fn:0x1080","include":["disasm"]}"#,
    );
    let rows = ghidorah_json::write(data(&rows));
    assert!(rows.contains("Make room on the stack."), "{rows}");
    let found = call(
        &mut session,
        "search",
        r#"{"kind":"comment","query":"stack"}"#,
    );
    assert_eq!(text_at(&found, "/data/items/0/addr"), "0x1084", "{found}");

    let changed = call(
        &mut session,
        "comment_set",
        r#"{"target":"0x1084","kind":"eol","text":"Align the stack."}"#,
    );
    assert_eq!(
        text_at(&changed, "/data/items/0/old"),
        "Make room on the stack."
    );
    assert_eq!(int_at(&changed, "/rev"), rev + 1);
    let deleted = call(
        &mut session,
        "comment_set",
        r#"{"target":"0x1084","kind":"eol","text":""}"#,
    );
    assert_eq!(
        deleted.pointer("/data/items/0/new"),
        Some(&Value::Null),
        "{deleted}"
    );
    assert_eq!(int_at(&deleted, "/rev"), rev + 2);
    let again = call(
        &mut session,
        "comment_set",
        r#"{"target":"0x1084","kind":"eol","text":""}"#,
    );
    assert_eq!(again.get("noop"), Some(&Value::Bool(true)), "{again}");
    assert_eq!(int_at(&again, "/rev"), rev + 2);
}

#[test]
fn comment_items_and_errors() {
    let (mut session, _) = fixture(STRIPPED);
    let envelope = call(
        &mut session,
        "comment_set",
        r#"{"items":[
            {"target":"fn:0x11e0","kind":"plate","text":"Checks the password."},
            {"target":"0x10","kind":"eol","text":"x"},
            {"target":"0x11e4","kind":"repeatable","text":"The length."}
        ]}"#,
    );
    let d = data(&envelope);
    assert_eq!(
        d.get("ok_count").and_then(Value::as_u64),
        Some(2),
        "{envelope}"
    );
    assert_eq!(d.get("error_count").and_then(Value::as_u64), Some(1));
    let list = items(&envelope);
    assert_eq!(text_at(&list[0], "/data/addr"), "0x11e0");
    assert_eq!(text_at(&list[1], "/error/code"), "ADDRESS_UNMAPPED");
    let cases = [
        (r#"{"target":"0x11e0","kind":"eol"}"#, "MISSING_ARGUMENT"),
        (r#"{"target":"0x11e0","text":"x"}"#, "MISSING_ARGUMENT"),
        (
            r#"{"target":"0x11e0","kind":"side","text":"x"}"#,
            "INVALID_ARGUMENT",
        ),
        (
            r#"{"items":[{"target":"0x11e0","kind":"eol","text":"x"}],"kind":"eol"}"#,
            "INVALID_ARGUMENT",
        ),
        (
            r#"{"target":"var:0x11e0/ret","kind":"eol","text":"x"}"#,
            "INVALID_ARGUMENT",
        ),
    ];
    for (args, want) in cases {
        let envelope = call(&mut session, "comment_set", args);
        assert_eq!(code(&envelope), want, "{args}: {envelope}");
    }
}
