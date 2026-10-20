//! The `history_undo` tool: undo, redo, scopes, conflicts and dry runs.

use ghidorah_base::FixedClock;
use ghidorah_json::Value;
use ghidorah_tools::{ContentMode, Host, Request, Session, dispatch_with};

use crate::support::{call, code, config, data, json, load_demo, rename, session_with, state};

#[test]
fn undo_and_redo_through_the_tool() {
    let mut s = session_with(config());
    let id = load_demo(&mut s);
    let start = state(&s, id);
    assert_eq!(code(&call(&mut s, "history_undo", "{}")), "NOTHING_TO_UNDO");
    assert_eq!(
        code(&call(&mut s, "history_undo", r#"{"redo":true}"#)),
        "NOTHING_TO_REDO"
    );
    rename(&mut s, id, "mcp-1", 0x1090, "first");
    let after = state(&s, id);
    let undo = call(&mut s, "history_undo", "{}");
    let undone = data(&undo);
    assert_eq!(
        undone.pointer("/undone/0/tx").and_then(Value::as_str),
        Some("tx:1")
    );
    assert_eq!(
        undone.pointer("/undone/0/session").and_then(Value::as_str),
        Some("mcp-1")
    );
    assert_eq!(undone.get("new_tx").and_then(Value::as_str), Some("tx:2"));
    assert_eq!(undo.get("tx").and_then(Value::as_str), Some("tx:2"));
    assert_eq!(state(&s, id).0, start.0);
    assert_eq!(state(&s, id).1, 2, "the undo is a new commit");
    let redo = call(&mut s, "history_undo", r#"{"redo":true}"#);
    assert_eq!(
        data(&redo).pointer("/redone/0/tx").and_then(Value::as_str),
        Some("tx:1")
    );
    assert_eq!(state(&s, id).0, after.0);
    assert_eq!(state(&s, id).1, 3);
}

#[test]
fn scopes_conflicts_and_dry_runs() {
    let mut s = session_with(config());
    let id = load_demo(&mut s);
    rename(&mut s, id, "mcp-1", 0x1090, "mine");
    rename(&mut s, id, "mcp-2", 0x1090, "theirs");
    // The caller's session is mcp-1, the label of the binary.
    let conflict = call(&mut s, "history_undo", "{}");
    assert_eq!(code(&conflict), "CONFLICT", "{conflict}");
    assert_eq!(
        conflict
            .pointer("/error/candidates/0/value")
            .and_then(Value::as_str),
        Some("tx:2")
    );
    let selective = call(&mut s, "history_undo", r#"{"tx":"tx:1"}"#);
    assert_eq!(code(&selective), "CONFLICT");
    let before = state(&s, id);
    let dry = call(&mut s, "history_undo", r#"{"session":"*","dry_run":true}"#);
    let planned = data(&dry);
    assert_eq!(
        planned.pointer("/undone/0/tx").and_then(Value::as_str),
        Some("tx:2")
    );
    assert_eq!(planned.get("new_tx"), Some(&Value::Null));
    assert_eq!(dry.get("noop"), Some(&Value::Bool(true)));
    assert_eq!(
        dry.pointer("/diff/0/op").and_then(Value::as_str),
        Some("SetName")
    );
    assert_eq!(state(&s, id), before, "a dry run changes nothing");
    let wide = call(&mut s, "history_undo", r#"{"session":"*","count":2}"#);
    let undone = data(&wide)
        .get("undone")
        .and_then(Value::as_array)
        .map(<[Value]>::len);
    assert_eq!(undone, Some(2), "{wide}");
    // The envelope names the label that commits the undo, not the scope.
    assert_eq!(wide.get("session").and_then(Value::as_str), Some("mcp-1"));
    assert_eq!(
        code(&call(&mut s, "history_undo", r#"{"tx":"note:1"}"#)),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        code(&call(&mut s, "history_undo", r#"{"tx":"tx:99"}"#)),
        "NOT_FOUND"
    );
}

/// Makes a session of the shipped registry with the demo binary open.
fn shipped_demo() -> Session {
    let mut s = Session::with_registry(
        <Session as Host>::registry(),
        config(),
        Box::new(FixedClock::new(0)),
    );
    let _ = load_demo(&mut s);
    s
}

/// Runs one call with two copies of the envelope in the result, as MCP `--content both` does.
fn call_both(session: &mut Session, tool: &str, args: &str) -> Value {
    let registry = session.active_registry();
    let mut request = Request::new(tool, json(args));
    request.content = ContentMode::Both;
    dispatch_with(&registry, session, &request).to_json()
}

/// Makes sure that `envelope` is a committed success: `ok`, `tx`, `rev` and `noop` false.
fn assert_committed(envelope: &Value) {
    assert_eq!(envelope.get("ok"), Some(&Value::Bool(true)), "{envelope}");
    assert!(
        envelope.get("tx").and_then(Value::as_str).is_some(),
        "{envelope}"
    );
    assert!(
        envelope.get("rev").and_then(Value::as_u64).is_some(),
        "{envelope}"
    );
    assert_eq!(
        envelope.get("noop"),
        Some(&Value::Bool(false)),
        "{envelope}"
    );
}

/// A committed edit never gives `OUTPUT_BUDGET_EXCEEDED`. A result that does not fit drops
/// data members, and `next[0]` reads the history since the rev before the call.
#[test]
fn regress_committed_edit_never_budget_fails() {
    let mut s = shipped_demo();
    for i in 0..12 {
        let args = format!(r#"{{"target":"0x1080","kind":"eol","text":"edit {i}"}}"#);
        assert_committed(&call(&mut s, "comment_set", &args));
    }
    let before = call(&mut s, "history_list", "{}")
        .get("rev")
        .and_then(Value::as_u64)
        .expect("a rev");
    let undo = call_both(&mut s, "history_undo", r#"{"count":10,"max_chars":1000}"#);
    assert_committed(&undo);
    assert!(ghidorah_json::write(&undo).chars().count() <= 500, "{undo}");
    assert_eq!(
        undo.pointer("/data/truncated"),
        Some(&Value::Bool(true)),
        "{undo}"
    );
    let omitted = undo.pointer("/data/omitted").and_then(Value::as_array);
    assert!(
        omitted.is_some_and(|o| o.contains(&Value::from("undone"))),
        "{undo}"
    );
    assert!(undo.pointer("/data/new_tx").is_some(), "{undo}");
    assert!(undo.pointer("/data/rev").is_some(), "{undo}");
    assert_eq!(
        undo.pointer("/next/0/tool").and_then(Value::as_str),
        Some("history_list"),
        "{undo}"
    );
    assert_eq!(
        undo.pointer("/next/0/args/since_rev")
            .and_then(Value::as_u64),
        Some(before),
        "{undo}"
    );
    let text = "n".repeat(900);
    let args = format!(r#"{{"kind":"finding","text":"{text}","max_chars":1000}}"#);
    let note = call_both(&mut s, "note_write", &args);
    assert_committed(&note);
    assert!(
        note.pointer("/data/note")
            .and_then(Value::as_str)
            .is_some_and(|id| id.starts_with("note:")),
        "{note}"
    );
    let item = format!(
        r#"{{"target":"0x1090","kind":"pre","text":"{}"}}"#,
        "c".repeat(1_500)
    );
    let items = vec![item; 5].join(",");
    let comments = call(&mut s, "comment_set", &format!(r#"{{"items":[{items}]}}"#));
    assert_committed(&comments);
    assert_eq!(
        comments.pointer("/data/truncated"),
        Some(&Value::Bool(true)),
        "{comments}"
    );
}
