//! AC-232 and the rows of `history_list`.

use ghidorah_json::Value;

use crate::support::{
    call, comment, config, config_in, items, load_demo, rename, session_with, tmp,
};

/// Gives `(id, last_rev, session)` of each coalesced item.
fn coalesced(items: &[Value]) -> Vec<(String, u64, String)> {
    items
        .iter()
        .map(|i| {
            (
                i.get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                i.get("last_rev").and_then(Value::as_u64).unwrap_or(0),
                i.get("session")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect()
}

fn row(id: &str, rev: u64, session: &str) -> (String, u64, String) {
    (id.to_owned(), rev, session.to_owned())
}

#[test]
fn ac_232_since_rev_coalesce() {
    let mut s = session_with(config());
    let id = load_demo(&mut s);
    assert_eq!(rename(&mut s, id, "mcp-1", 0x1090, "first"), 1);
    assert_eq!(rename(&mut s, id, "mcp-2", 0x1094, "second"), 2);
    assert_eq!(rename(&mut s, id, "mcp-2", 0x1090, "third"), 3);
    assert_eq!(comment(&mut s, id, "mcp-1", 0x10a0, "a note"), 4);
    let all = items(&call(&mut s, "history_list", r#"{"since_rev":0}"#));
    assert_eq!(
        coalesced(&all),
        vec![
            row("0x1094", 2, "mcp-2"),
            row("0x1090", 3, "mcp-2"),
            row("0x10a0", 4, "mcp-1"),
        ]
    );
    let name = all
        .get(1)
        .and_then(|i| i.pointer("/fields/name"))
        .and_then(Value::as_str);
    assert_eq!(name, Some("third"), "{all:?}");
    assert_eq!(
        all.first()
            .and_then(|i| i.get("kind"))
            .and_then(Value::as_str),
        Some("name")
    );
    assert_eq!(
        all.get(2)
            .and_then(|i| i.get("kind"))
            .and_then(Value::as_str),
        Some("comment")
    );
    let since = items(&call(&mut s, "history_list", r#"{"since_rev":2}"#));
    assert_eq!(
        coalesced(&since),
        vec![row("0x1090", 3, "mcp-2"), row("0x10a0", 4, "mcp-1")]
    );
    let own = items(&call(
        &mut s,
        "history_list",
        r#"{"since_rev":0,"session":"mcp-2"}"#,
    ));
    assert_eq!(
        coalesced(&own),
        vec![row("0x1094", 2, "mcp-2"), row("0x1090", 3, "mcp-2")]
    );
    let others = items(&call(
        &mut s,
        "history_list",
        r#"{"since_rev":0,"exclude_session":"mcp-2","kinds":["name"]}"#,
    ));
    assert_eq!(coalesced(&others), vec![row("0x1090", 1, "mcp-1")]);
    let raw = items(&call(
        &mut s,
        "history_list",
        r#"{"since_rev":0,"coalesce":false}"#,
    ));
    assert_eq!(raw.len(), 4, "{raw:?}");
    let first = raw.first().expect("a raw row");
    assert_eq!(first.get("tx").and_then(Value::as_str), Some("tx:1"));
    assert_eq!(
        first.get("label").and_then(Value::as_str),
        Some("symbol_rename")
    );
    assert_eq!(first.get("source").and_then(Value::as_str), Some("agent"));
    assert_eq!(
        first.pointer("/fields/evidence/0").and_then(Value::as_str),
        Some("fn:0x1080")
    );
}

#[test]
fn rows_follow_undo_and_survive_a_reopen() {
    let dir = tmp("rows_reopen");
    let mut s = session_with(config_in(&dir));
    let id = load_demo(&mut s);
    rename(&mut s, id, "mcp-1", 0x1090, "first");
    rename(&mut s, id, "mcp-1", 0x1090, "second");
    let undo = call(&mut s, "history_undo", "{}");
    assert_eq!(undo.get("rev").and_then(Value::as_u64), Some(3), "{undo}");
    let raw = items(&call(
        &mut s,
        "history_list",
        r#"{"since_rev":0,"coalesce":false}"#,
    ));
    assert_eq!(raw.len(), 3, "{raw:?}");
    assert_eq!(
        raw.get(1)
            .and_then(|r| r.get("undone_by"))
            .and_then(Value::as_str),
        Some("tx:3")
    );
    let before = items(&call(&mut s, "history_list", r#"{"since_rev":0}"#));
    assert_eq!(before.len(), 1);
    assert_eq!(
        before
            .first()
            .and_then(|r| r.pointer("/fields/name"))
            .and_then(Value::as_str),
        Some("first")
    );
    drop(s);
    let mut again = session_with(config_in(&dir));
    let open = call(
        &mut again,
        "binary_load",
        &format!(r#"{{"binary_id":"{}"}}"#, crate::support::DEMO_ID),
    );
    assert_eq!(open.get("rev").and_then(Value::as_u64), Some(3), "{open}");
    let after = items(&call(&mut again, "history_list", r#"{"since_rev":0}"#));
    assert_eq!(after, before, "the rows come from the journal");
}
