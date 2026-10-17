//! AC-233: MCP default session labels are `mcp-<k>` per process and binary, and every
//! envelope echoes `session`.
//!
//! A project gives `k` as 1 plus the number of distinct `mcp-` labels in its journal. The
//! golden v1 project has the label `mcp-1`, so a new process gets `mcp-2` for it. A new
//! project gets `mcp-1`.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

#[path = "common/mod.rs"]
mod common;

#[path = "common/child.rs"]
mod child;

use ghidorah_json::Value;

use crate::child::{Server, copy_golden, demo_args};
use crate::common::tmp;

fn session_of(envelope: &Value) -> Option<&str> {
    envelope.get("session").and_then(Value::as_str)
}

#[test]
fn ac_233_session_labels() {
    let projects = tmp("ac_233");
    copy_golden(&projects);
    let root_arg = projects.to_string_lossy().into_owned();
    let mut server = Server::spawn(&["--project-root", root_arg.as_str()]);
    let mut envelopes = Vec::new();
    let golden = server.call("binary_load", demo_args());
    assert_eq!(session_of(&golden), Some("mcp-2"), "{golden}");
    envelopes.push(golden);
    let path = Value::object([
        ("path", Value::from("fixtures/bin/hello.gcc-O2")),
        ("analysis", Value::from("none")),
    ]);
    let fresh = server.call("binary_load", path);
    assert_eq!(session_of(&fresh), Some("mcp-1"), "{fresh}");
    let id = fresh
        .pointer("/data/binary_id")
        .and_then(Value::as_str)
        .expect("a binary ID")
        .to_owned();
    envelopes.push(fresh);
    // Two open binaries: a call without binary_id fails, and the failure echoes a session.
    let calc = server.call("calc", Value::object([("expr", Value::from("1+1"))]));
    envelopes.push(calc);
    let again = server.call(
        "binary_load",
        Value::object([("binary_id", Value::from(id))]),
    );
    assert_eq!(
        session_of(&again),
        Some("mcp-1"),
        "the label stays per binary"
    );
    envelopes.push(again);
    let named = server.call(
        "binary_load",
        Value::object([
            ("binary_id", Value::from(child::DEMO_ID)),
            ("session", Value::from("planner")),
        ]),
    );
    assert_eq!(session_of(&named), Some("planner"));
    envelopes.push(named);
    for envelope in &envelopes {
        assert!(session_of(envelope).is_some(), "{envelope}");
    }
    server.close();
    // A second process gets the same labels: the journals have no new mcp- label.
    let mut next = Server::spawn(&["--project-root", root_arg.as_str()]);
    let reopened = next.call("binary_load", demo_args());
    assert_eq!(session_of(&reopened), Some("mcp-2"));
    next.close();
}
