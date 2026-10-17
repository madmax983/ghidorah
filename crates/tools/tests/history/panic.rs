//! AC-148: a handler panic gives `INTERNAL_ERROR` with a crash ID, and the program reloads.

use ghidorah_json::Value;

use crate::support::{
    call, code, config, config_in, data, load_demo, rename, session_with, state, tmp,
};

/// Runs the panic tool and checks the error, the next call and the state.
fn panic_keeps_the_state(session: &mut ghidorah_tools::Session) -> String {
    let id = load_demo(session);
    rename(session, id, "mcp-1", 0x1090, "read_input");
    let before = state(session, id);
    let envelope = call(session, "test_boom", "{}");
    assert_eq!(code(&envelope), "INTERNAL_ERROR", "{envelope}");
    let crash = envelope
        .pointer("/error/crash_id")
        .and_then(Value::as_str)
        .expect("a crash ID")
        .to_owned();
    assert_eq!(crash.len(), 16, "{crash}");
    let next = call(session, "history_list", r#"{"since_rev":0}"#);
    data(&next);
    assert_eq!(next.get("rev").and_then(Value::as_u64), Some(before.1));
    assert_eq!(state(session, id), before, "the reload keeps the state");
    crash
}

#[test]
fn ac_148_panic_isolation() {
    // A project on disk: the reload reads the snapshot and the journal.
    let dir = tmp("ac_148");
    let mut session = session_with(config_in(&dir));
    let crash = panic_keeps_the_state(&mut session);
    let file = dir
        .join(crate::support::DEMO_ID)
        .join("crash")
        .join(format!("{crash}.json"));
    let text = std::fs::read_to_string(&file).expect("the crash record exists");
    let record = crate::support::json(&text);
    assert_eq!(
        record.get("tool").and_then(Value::as_str),
        Some("test_boom")
    );
    assert_eq!(record.get("rev").and_then(Value::as_u64), Some(1));
    assert!(record.get("panic").and_then(Value::as_str).is_some());
    assert_eq!(session.crashes().len(), 1);
    // A session in memory: the reload replays the history over the checkpoint.
    let mut memory = session_with(config());
    panic_keeps_the_state(&mut memory);
}
