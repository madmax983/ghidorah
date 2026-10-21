//! AC-253: the PE transcript `tests/golden/mcp/e2e_pe.jsonl` over a spawned `ghidorah mcp`
//! (design Sections 4.15 and 14.1).
//!
//! The client loads `pe_main.exe`, surveys it, lists the functions and reads the switch function
//! `classify` with `include decomp`. The survey groups the imports by DLL, and the C text of
//! `classify` holds a `switch` statement. Later WPs bless the server lines again with
//! `GHIDORAH_BLESS=1`.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

#[path = "common/mod.rs"]
mod common;

use ghidorah_json::Value;

use crate::common::transcript::{ClientLine, check, clients, run_spawned};
use crate::common::{json, root, tmp};

/// Gives the structured content of the reply with the JSON-RPC `id` in `steps`.
fn reply(steps: &[(ClientLine, Vec<String>)], id: u64) -> Value {
    let message = steps
        .iter()
        .flat_map(|(_, lines)| lines)
        .map(|line| json(line))
        .find(|m| m.get("id").and_then(Value::as_u64) == Some(id))
        .unwrap_or_else(|| panic!("no reply with the id {id}"));
    message
        .pointer("/result/structuredContent")
        .cloned()
        .unwrap_or_else(|| panic!("the reply {id} has structured content: {message}"))
}

/// Gives the text at `pointer` of `value`, or an empty text.
fn text(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn ac_253_pe_end_to_end() {
    let clients = clients("e2e_pe");
    assert_eq!(clients.len(), 6, "the handshake and four tool calls");
    let projects = tmp("e2e_pe_projects");
    let project_root = projects.to_string_lossy().into_owned();
    let workspace = root().to_string_lossy().into_owned();
    let args = [
        "--project-root",
        project_root.as_str(),
        "--root",
        workspace.as_str(),
    ];
    let steps = run_spawned(&args, &clients);
    check("e2e_pe", &steps);
    let load = reply(&steps, 2);
    assert_eq!(text(&load, "/data/format"), "pe32+-x86_64", "{load}");
    assert_eq!(text(&load, "/data/analysis/state"), "complete", "{load}");
    let survey = reply(&steps, 3);
    let items = survey
        .pointer("/data/imports/items")
        .and_then(Value::as_array)
        .expect("the import items");
    let mut dlls: Vec<String> = items.iter().map(|i| text(i, "/dll")).collect();
    dlls.dedup();
    assert_eq!(
        dlls,
        vec!["kernel32.dll", "alpha.dll", "beta.dll"],
        "{survey}"
    );
    let list = reply(&steps, 4);
    let ids: Vec<String> = list
        .pointer("/data/items")
        .and_then(Value::as_array)
        .expect("the function items")
        .iter()
        .map(|f| text(f, "/id"))
        .collect();
    assert!(ids.contains(&"fn:0x140001010".to_owned()), "{ids:?}");
    let classify = reply(&steps, 5);
    let decomp = text(&classify, "/data/decomp/text");
    assert!(
        decomp.contains("switch"),
        "the C text has a switch: {classify}"
    );
}
