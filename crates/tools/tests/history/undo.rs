//! The `history_undo` tool: undo, redo, scopes, conflicts and dry runs.

use ghidorah_json::Value;

use crate::support::{call, code, config, data, load_demo, rename, session_with, state};

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
    assert_eq!(wide.get("session").and_then(Value::as_str), Some("*"));
    assert_eq!(
        code(&call(&mut s, "history_undo", r#"{"tx":"note:1"}"#)),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        code(&call(&mut s, "history_undo", r#"{"tx":"tx:99"}"#)),
        "NOT_FOUND"
    );
}
