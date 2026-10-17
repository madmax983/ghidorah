//! `note_write`: the note kinds, updates, deletes, findings and the records of
//! `search { ids }` (AC-218).

use ghidorah_json::Value;

use crate::support::{
    STRIPPED, all_items, call, code, data, fixture, int_at, json, str_of, text_at, warnings,
};

#[test]
fn note_kinds_and_records() {
    let (mut session, _) = fixture(STRIPPED);
    let todo = call(
        &mut session,
        "note_write",
        r#"{"kind":"todo","text":"Read the password check.","at":"0x11e8","tags":["auth"]}"#,
    );
    assert_eq!(text_at(&todo, "/data/note"), "note:1", "{todo}");
    assert_eq!(text_at(&todo, "/data/kind"), "todo");
    assert_eq!(text_at(&todo, "/data/status"), "open");
    assert_eq!(int_at(&todo, "/data/rev"), int_at(&todo, "/rev"));
    let hypothesis = call(
        &mut session,
        "note_write",
        r#"{"kind":"hypothesis","text":"main calls strlen.","claims":[{"rel":"calls","args":["fn:0x1080","imp:strlen"]}]}"#,
    );
    assert_eq!(text_at(&hypothesis, "/data/note"), "note:2", "{hypothesis}");
    let records = call(&mut session, "search", r#"{"ids":["note:1","note:2"]}"#);
    let list = data(&records)
        .get("items")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default();
    assert_eq!(list.len(), 2, "{records}");
    let by_id = |id: &str| {
        list.iter()
            .find(|i| str_of(i, "id") == id)
            .cloned()
            .expect("the record exists")
    };
    let (first, second) = (by_id("note:1"), by_id("note:2"));
    let first = &first;
    assert_eq!(str_of(first, "addr"), "0x11e8");
    assert_eq!(
        str_of(first, "func"),
        "fn:0x11e0",
        "the note names its function"
    );
    assert_eq!(text_at(first, "/extra/kind"), "todo");
    assert_eq!(first.pointer("/extra/tags"), Some(&json(r#"["auth"]"#)));
    assert_eq!(
        second.pointer("/extra/claims"),
        Some(&json(
            r#"[{"rel":"calls","args":["fn:0x1080","imp:strlen"]}]"#
        )),
        "{records}"
    );
}

#[test]
fn note_update_and_delete() {
    let (mut session, _) = fixture(STRIPPED);
    let made = call(
        &mut session,
        "note_write",
        r#"{"kind":"todo","text":"Read main.","tags":["a"]}"#,
    );
    assert_eq!(text_at(&made, "/data/note"), "note:1", "{made}");
    let done = call(
        &mut session,
        "note_write",
        r#"{"target":"note:1","status":"done"}"#,
    );
    assert_eq!(text_at(&done, "/data/status"), "done", "{done}");
    assert_eq!(
        text_at(&done, "/data/kind"),
        "todo",
        "an update keeps the kind"
    );
    let record = call(&mut session, "search", r#"{"ids":["note:1"]}"#);
    assert_eq!(
        text_at(&record, "/data/items/0/text"),
        "Read main.",
        "{record}"
    );
    assert_eq!(
        record.pointer("/data/items/0/extra/tags"),
        Some(&json(r#"["a"]"#)),
        "an update keeps the fields that it does not name"
    );
    let same = call(
        &mut session,
        "note_write",
        r#"{"target":"note:1","status":"done"}"#,
    );
    assert_eq!(same.get("noop"), Some(&Value::Bool(true)), "{same}");
    let gone = call(
        &mut session,
        "note_write",
        r#"{"target":"note:1","delete":true}"#,
    );
    assert_eq!(
        gone.pointer("/data/deleted"),
        Some(&Value::Bool(true)),
        "{gone}"
    );
    let missing = call(&mut session, "search", r#"{"ids":["note:1"]}"#);
    assert_eq!(code(&missing), "NOT_FOUND", "{missing}");
    let again = call(
        &mut session,
        "note_write",
        r#"{"target":"note:1","delete":true}"#,
    );
    assert_eq!(code(&again), "NOT_FOUND", "{again}");
    let next = call(
        &mut session,
        "note_write",
        r#"{"kind":"note","text":"A new note."}"#,
    );
    assert_eq!(
        text_at(&next, "/data/note"),
        "note:2",
        "IDs never come back: {next}"
    );
}

#[test]
fn findings_and_errors() {
    let (mut session, _) = fixture(STRIPPED);
    let bare = call(
        &mut session,
        "note_write",
        r#"{"kind":"finding","text":"The check is weak.","at":"0x11e0"}"#,
    );
    assert_eq!(warnings(&bare, "W_UNGROUNDED_FINDING"), 1, "{bare}");
    let grounded = call(
        &mut session,
        "note_write",
        r#"{"kind":"finding","text":"The check is weak.","evidence":["fn:0x11e0"]}"#,
    );
    assert_eq!(warnings(&grounded, "W_UNGROUNDED_FINDING"), 0, "{grounded}");
    let fixed = call(
        &mut session,
        "note_write",
        r#"{"target":"note:1","evidence":["fn:0x11e0"]}"#,
    );
    assert_eq!(warnings(&fixed, "W_UNGROUNDED_FINDING"), 0, "{fixed}");
    let cases = [
        (r#"{"kind":"set"}"#, "MISSING_ARGUMENT"),
        (r#"{"kind":"todo"}"#, "MISSING_ARGUMENT"),
        (
            r#"{"kind":"todo","text":"x","set":{"name":"a"}}"#,
            "INVALID_ARGUMENT",
        ),
        (
            r#"{"kind":"finding","text":"x","evidence":["nonsense"]}"#,
            "INVALID_ARGUMENT",
        ),
        (r#"{"target":"note:99","status":"done"}"#, "NOT_FOUND"),
        (
            r#"{"delete":true,"kind":"todo","text":"x"}"#,
            "INVALID_ARGUMENT",
        ),
        (r#"{"target":"note:1","kind":"set"}"#, "MISSING_ARGUMENT"),
        (
            r#"{"kind":"note","text":"x","at":"0x900000"}"#,
            "ADDRESS_UNMAPPED",
        ),
    ];
    for (args, want) in cases {
        let envelope = call(&mut session, "note_write", args);
        assert_eq!(code(&envelope), want, "{args}: {envelope}");
    }
}

#[test]
fn ac_218_search_ids() {
    let (mut session, _) = fixture("switch.gcc-O2");
    let tables = call(&mut session, "search", r#"{"kind":"jumptable"}"#);
    let jt = text_at(&tables, "/data/items/0/id");
    assert!(jt.starts_with("jt:"), "{tables}");
    let note = call(
        &mut session,
        "note_write",
        r#"{"kind":"hypothesis","text":"The switch has a default case.","claims":[{"rel":"noreturn","args":["fn:0x1080"]}],"evidence":["fn:0x1080"],"tags":["switch"]}"#,
    );
    assert_eq!(code(&note), "", "{note}");
    let members: Vec<Value> = (0..120u64)
        .map(|i| Value::from(format!("fn:0x{:x}", 0x10_000 + i * 16)))
        .collect();
    let set = Value::object([
        ("kind", Value::from("set")),
        (
            "set",
            Value::object([
                ("name", Value::from("big")),
                ("members", Value::Array(members.clone())),
            ]),
        ),
    ]);
    let made = crate::support::call_value(&mut session, "note_write", set);
    assert_eq!(text_at(&made, "/data/set"), "set:big", "{made}");
    assert_eq!(int_at(&made, "/data/members"), 120);
    let args = Value::object([(
        "ids",
        Value::Array(vec![
            Value::from("note:1"),
            Value::from("set:big"),
            Value::from(jt.as_str()),
        ]),
    )]);
    let all = all_items(&mut session, "search", &args, 50);
    assert_eq!(
        all.len(),
        1 + 1 + 120 + 1,
        "a record, a set record, 120 members, a table"
    );
    let record = &all[0];
    assert_eq!(str_of(record, "id"), "note:1");
    assert_eq!(str_of(record, "text"), "The switch has a default case.");
    for key in [
        "kind", "status", "tags", "evidence", "claims", "src", "session", "rev",
    ] {
        assert!(
            record.get("extra").and_then(|e| e.get(key)).is_some(),
            "{key}: {record}"
        );
    }
    let set_record = &all[1];
    assert_eq!(str_of(set_record, "id"), "set:big");
    assert_eq!(
        set_record.pointer("/extra/members").and_then(Value::as_u64),
        Some(120)
    );
    let paged: Vec<Value> = all[2..122]
        .iter()
        .filter_map(|i| i.pointer("/extra/member").cloned())
        .collect();
    let mut want = members;
    want.sort_by_key(|v| v.as_str().unwrap_or_default().to_owned());
    assert_eq!(paged, want, "the cursor pages every member once");
    assert_eq!(str_of(&all[122], "id"), jt);
}
