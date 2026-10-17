//! The walking skeleton: `tests/golden/mcp/e2e.jsonl` over a spawned `ghidorah mcp`
//! (design Section 14.1).
//!
//! Version 1 holds the legacy handshake and `tools/list`. Later WPs add client lines and
//! bless the server lines again with `GHIDORAH_BLESS=1`.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

#[path = "common/mod.rs"]
mod common;

use ghidorah_json::Value;

use crate::common::json;
use crate::common::transcript::{check, clients, run_spawned};

#[test]
fn e2e_elf_x86_64() {
    let clients = clients("e2e");
    assert!(
        clients.len() >= 3,
        "version 1 has the handshake and tools/list"
    );
    let steps = run_spawned(&[], &clients);
    check("e2e", &steps);
    let init = json(&steps[0].1[0]);
    assert_eq!(
        init.pointer("/result/serverInfo/name")
            .and_then(Value::as_str),
        Some("ghidorah")
    );
    let list = json(steps[2].1.last().expect("a tools/list reply"));
    assert!(
        list.pointer("/result/tools")
            .and_then(Value::as_array)
            .is_some()
    );
}
