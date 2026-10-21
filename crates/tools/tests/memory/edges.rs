//! The edge cases of the memory tools: dry runs, read-only binaries, briefs with more than one
//! open binary, range members, set name conflicts and note updates.

use ghidorah_json::Value;
use ghidorah_tools::OpenBinary;

use crate::support::{
    DEMO_ID, STRIPPED, analyzed, call, code, data, fixture, int_at, items, next0, program, session,
    str_of, text_at,
};

#[test]
fn dry_runs_of_comments_and_notes() {
    let (mut session, id) = fixture(STRIPPED);
    let rev = program(&session, id).rev().0;
    let comment = call(
        &mut session,
        "comment_set",
        r#"{"target":"0x1084","kind":"eol","text":"x","dry_run":true}"#,
    );
    assert_eq!(text_at(&comment, "/diff/0/op"), "SetComment", "{comment}");
    assert_eq!(comment.get("noop"), Some(&Value::Bool(true)));
    let note = call(
        &mut session,
        "note_write",
        r#"{"kind":"todo","text":"x","dry_run":true}"#,
    );
    assert_eq!(text_at(&note, "/diff/0/op"), "WriteNote", "{note}");
    let p = program(&session, id);
    assert_eq!(p.rev().0, rev, "a dry run commits nothing");
    assert!(p.notes().is_empty());
    assert!(
        p.comment(
            ghidorah_base::Address::ram(0x1084),
            ghidorah_db::CommentKind::Eol
        )
        .is_none()
    );
}

#[test]
fn read_only_binary_takes_dry_runs_only() {
    let found = analyzed(STRIPPED);
    let mut s = session();
    let label = s.new_label();
    s.open(OpenBinary {
        id: found.id,
        program: found.program.clone(),
        file_name: found.file_name.clone(),
        read_only: true,
        label,
        analysis: found.analysis,
    });
    let refused = call(
        &mut s,
        "symbol_rename",
        r#"{"target":"fn:0x11e0","name":"check_password"}"#,
    );
    assert_eq!(code(&refused), "READ_ONLY_PROJECT", "{refused}");
    let dry = call(
        &mut s,
        "symbol_rename",
        r#"{"target":"fn:0x11e0","name":"check_password","dry_run":true}"#,
    );
    assert_eq!(code(&dry), "", "{dry}");
    let brief = call(&mut s, "session_brief", "{}");
    assert_eq!(
        brief.pointer("/data/binaries/0/read_only"),
        Some(&Value::Bool(true)),
        "{brief}"
    );
}

#[test]
fn brief_with_two_binaries() {
    let (mut session, stripped) = fixture(STRIPPED);
    let demo = call(&mut session, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(code(&demo), "", "{demo}");
    let renamed = call(
        &mut session,
        "symbol_rename",
        &format!(
            r#"{{"binary_id":"{DEMO_ID}","target":"fn:0x11e0","name":"check_pw","force":true}}"#
        ),
    );
    assert_eq!(code(&renamed), "", "{renamed}");
    let brief = call(&mut session, "session_brief", "{}");
    assert!(
        brief.get("binary_id").is_none(),
        "no binary is bound: {brief}"
    );
    assert_eq!(
        text_at(&brief, "/data/binary_id"),
        DEMO_ID,
        "the most recent binary"
    );
    assert_eq!(
        data(&brief)
            .get("binaries")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(2)
    );
    let (tool, args) = next0(&brief);
    assert_eq!(tool, "history_list", "{brief}");
    assert_eq!(str_of(&args, "binary_id"), DEMO_ID);
    let other = call(
        &mut session,
        "session_brief",
        &format!(r#"{{"binary_id":"{stripped}"}}"#),
    );
    assert_eq!(
        text_at(&other, "/data/binary_id"),
        stripped.to_string(),
        "{other}"
    );
    assert!(
        data(&other)
            .get("weak_names")
            .and_then(Value::as_array)
            .is_some_and(|w| !w.is_empty()),
        "{other}"
    );
}

#[test]
fn range_members_and_set_conflicts() {
    let (mut session, _) = fixture(STRIPPED);
    let made = call(
        &mut session,
        "note_write",
        r#"{"kind":"set","set":{"name":"a","members":[{"start":"0x1080","end":"0x1090"},"0x11e0",{"start":4416,"size":16}]}}"#,
    );
    assert_eq!(int_at(&made, "/data/ranges"), 3, "{made}");
    let funcs = call(&mut session, "func_list", r#"{"in":"set:a"}"#);
    let ids: Vec<String> = items(&funcs).iter().map(|i| str_of(i, "id")).collect();
    assert_eq!(ids, ["fn:0x1080", "fn:0x1140", "fn:0x11e0"], "{funcs}");
    let b = call(
        &mut session,
        "note_write",
        r#"{"kind":"set","set":{"name":"b","members":["fn:0x1080"]}}"#,
    );
    assert_eq!(text_at(&b, "/data/note"), "note:2", "{b}");
    let taken = call(
        &mut session,
        "note_write",
        r#"{"target":"note:2","set":{"name":"a","members":["fn:0x1110"],"op":"union"}}"#,
    );
    assert_eq!(code(&taken), "CONFLICT", "{taken}");
    let renamed = call(
        &mut session,
        "note_write",
        r#"{"target":"note:2","set":{"name":"c","op":"union"}}"#,
    );
    assert_eq!(text_at(&renamed, "/data/set"), "set:c", "{renamed}");
    assert_eq!(
        int_at(&renamed, "/data/members"),
        1,
        "an empty operand keeps the members"
    );
    for args in [
        r#"{"kind":"set","set":{"name":"d","members":[{"start":"0x1080","end":"0x1080"}]}}"#,
        r#"{"kind":"set","set":{"name":"d","members":[{"start":"0x1080","size":1,"extra":1}]}}"#,
        r#"{"kind":"set","set":{"name":"d","members":[{"start":"0x1080","size":1,"end":"0x1090"}]}}"#,
        r#"{"kind":"set","set":{"name":"d","members":["nonsense"]}}"#,
    ] {
        let envelope = call(&mut session, "note_write", args);
        assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{args}: {envelope}");
    }
    let empty = call(
        &mut session,
        "note_write",
        r#"{"kind":"set","set":{"name":"e","members":["fn:0x1080"],"op":"intersect"}}"#,
    );
    assert_eq!(int_at(&empty, "/data/members"), 0, "{empty}");
}

#[test]
fn note_updates_change_fields() {
    let (mut session, _) = fixture(STRIPPED);
    let made = call(
        &mut session,
        "note_write",
        r#"{"kind":"todo","text":"Read main."}"#,
    );
    assert_eq!(code(&made), "", "{made}");
    let changed = call(
        &mut session,
        "note_write",
        r#"{"target":"note:1","kind":"hypothesis","text":"main calls puts.","at":"main","tags":["io"],"evidence":["fn:0x1080"],"claims":[{"rel":"calls","args":["fn:0x1080","imp:puts"]}],"status":"confirmed"}"#,
    );
    assert_eq!(text_at(&changed, "/data/kind"), "hypothesis", "{changed}");
    assert_eq!(text_at(&changed, "/data/status"), "confirmed");
    let record = call(&mut session, "search", r#"{"ids":["note:1"]}"#);
    let item = items(&record).first().cloned().unwrap_or_default();
    assert_eq!(str_of(&item, "text"), "main calls puts.", "{record}");
    assert_eq!(str_of(&item, "func"), "fn:0x1080");
    assert_eq!(text_at(&item, "/extra/claims/0/rel"), "calls");
    let to_set = call(
        &mut session,
        "note_write",
        r#"{"target":"note:1","kind":"set","set":{"name":"x"}}"#,
    );
    assert_eq!(code(&to_set), "INVALID_ARGUMENT", "{to_set}");
    let bad_items = call(
        &mut session,
        "symbol_rename",
        r#"{"items":[{"target":"fn:0x11e0","name":""},{"target":"var:0x1088/ret","name":"r"}]}"#,
    );
    let list = items(&bad_items);
    assert_eq!(
        text_at(&list[0], "/error/code"),
        "INVALID_ARGUMENT",
        "{bad_items}"
    );
    assert_eq!(text_at(&list[0], "/error/field_path"), "/items/0/name");
    assert_eq!(text_at(&list[1], "/error/code"), "NOT_FOUND");
    assert_eq!(
        bad_items.get("noop"),
        Some(&Value::Bool(true)),
        "no item commits"
    );
}
