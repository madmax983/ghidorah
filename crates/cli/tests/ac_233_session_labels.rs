//! AC-233: MCP default session labels are `mcp-<k>` per process and binary, and every
//! envelope echoes `session`.
//!
//! A project gives `k` as 1 plus the number of distinct `mcp-` labels in its journal. The
//! golden v1 project has the label `mcp-1`, so a new process gets `mcp-2` for it. A new
//! project gets `mcp-1`. The first process writes one edit as `mcp-2`, so the next process
//! gets `mcp-3`. The test copies the golden project to a temporary directory first.

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

/// The calls of one server process. Each envelope must echo `session`.
struct Calls {
    server: Server,
    envelopes: Vec<Value>,
}

impl Calls {
    fn new(root_arg: &str) -> Self {
        Self {
            server: Server::spawn(&["--project-root", root_arg]),
            envelopes: Vec::new(),
        }
    }

    /// Runs one call and keeps its envelope.
    fn call(&mut self, tool: &str, args: Value) -> Value {
        let envelope = self.server.call(tool, args);
        self.envelopes.push(envelope.clone());
        envelope
    }

    /// Checks the session member of every envelope, then closes the server.
    fn close(self) {
        assert!(!self.envelopes.is_empty());
        for envelope in &self.envelopes {
            assert!(session_of(envelope).is_some(), "{envelope}");
        }
        self.server.close();
    }
}

#[test]
fn ac_233_session_labels() {
    let projects = tmp("ac_233");
    copy_golden(&projects);
    let root_arg = projects.to_string_lossy().into_owned();
    let mut server = Calls::new(&root_arg);
    let golden = server.call("binary_load", demo_args());
    assert_eq!(session_of(&golden), Some("mcp-2"), "{golden}");
    // One edit on the demo as mcp-2: the journal of the project gets a second mcp- label.
    let rename = server.call(
        "symbol_rename",
        Value::object([
            ("binary_id", Value::from(child::DEMO_ID)),
            ("target", Value::from("0x1094")),
            ("name", Value::from("check_len")),
        ]),
    );
    assert_eq!(
        rename.get("ok"),
        Some(&Value::Bool(true)),
        "the edit commits: {rename}"
    );
    assert!(
        rename.get("tx").and_then(Value::as_str).is_some(),
        "a new commit: {rename}"
    );
    assert_eq!(session_of(&rename), Some("mcp-2"), "{rename}");
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
    // Two open binaries: a call without binary_id fails, and the failure echoes a session.
    let calc = server.call("calc", Value::object([("expr", Value::from("1+1"))]));
    assert_eq!(calc.get("ok"), Some(&Value::Bool(false)), "{calc}");
    let again = server.call(
        "binary_load",
        Value::object([("binary_id", Value::from(id.as_str()))]),
    );
    assert_eq!(
        session_of(&again),
        Some("mcp-1"),
        "the label stays per binary"
    );
    let named = server.call(
        "binary_load",
        Value::object([
            ("binary_id", Value::from(child::DEMO_ID)),
            ("session", Value::from("planner")),
        ]),
    );
    assert_eq!(session_of(&named), Some("planner"));
    let demo = server.call("binary_load", demo_args());
    assert_eq!(session_of(&demo), Some("mcp-2"), "the label of the process");
    server.close();
    // The next process: the demo journal holds mcp-1 and mcp-2, so the label is mcp-3.
    let mut next = Calls::new(&root_arg);
    let reopened = next.call("binary_load", demo_args());
    assert_eq!(session_of(&reopened), Some("mcp-3"), "{reopened}");
    let read = next.call(
        "addr_info",
        Value::object([
            ("binary_id", Value::from(child::DEMO_ID)),
            ("target", Value::from("0x1094")),
        ]),
    );
    assert_eq!(session_of(&read), Some("mcp-3"), "{read}");
    assert_eq!(
        read.pointer("/data/symbol/name").and_then(Value::as_str),
        Some("check_len"),
        "the edit of the first process persists: {read}"
    );
    next.close();
}
