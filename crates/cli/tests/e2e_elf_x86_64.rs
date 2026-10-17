//! The walking skeleton: `tests/golden/mcp/e2e.jsonl` over a spawned `ghidorah mcp`
//! (design Section 14.1).
//!
//! Version 1 holds the legacy handshake and `tools/list`. The next versions spawn the server
//! with a new projects root. It loads the demo binary, which runs the analysis. Then it calls
//! the read tools `binary_survey`, `func_list`, `func_get` and `xref_list` (version 2), and
//! `analysis_run`, `history_list` and a dry run of `history_undo` (version 3), and
//! `func_get include decomp` (version 6). Later WPs add client lines and bless the server
//! lines again with `GHIDORAH_BLESS=1`.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

#[path = "common/mod.rs"]
mod common;

use ghidorah_json::Value;

use crate::common::transcript::{check, clients, run_spawned};
use crate::common::{json, tmp};

/// Gives the reply of the tool call with the JSON-RPC `id` in `steps`.
fn reply(steps: &[(crate::common::transcript::ClientLine, Vec<String>)], id: u64) -> Value {
    steps
        .iter()
        .flat_map(|(_, lines)| lines)
        .map(|line| json(line))
        .find(|m| m.get("id").and_then(Value::as_u64) == Some(id))
        .unwrap_or_else(|| panic!("no reply with the id {id}"))
}

/// Gives the text of `pointer` in the structured content of a tool reply.
fn text<'a>(reply: &'a Value, pointer: &str) -> Option<&'a str> {
    reply
        .pointer(&format!("/result/structuredContent{pointer}"))
        .and_then(Value::as_str)
}

#[test]
fn e2e_elf_x86_64() {
    let clients = clients("e2e");
    assert!(
        clients.len() >= 12,
        "the transcript has the handshake, tools/list and the tool calls"
    );
    let projects = tmp("e2e_projects");
    let root = projects.to_string_lossy().into_owned();
    let steps = run_spawned(&["--project-root", root.as_str()], &clients);
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
    let load = reply(&steps, 3);
    assert_eq!(
        text(&load, "/data/analysis/state"),
        Some("complete"),
        "{load}"
    );
    assert!(
        projects.join("467a43b75d95c826/journal.jsonl").exists(),
        "binary_load makes the project of the demo binary"
    );
    for id in 4..=7 {
        let read = reply(&steps, id);
        assert_eq!(
            read.pointer("/result/structuredContent/ok"),
            Some(&Value::Bool(true)),
            "{read}"
        );
    }
    let survey = reply(&steps, 4);
    assert_eq!(
        text(&survey, "/binary_id"),
        Some("467a43b75d95c826"),
        "binary_survey uses the open binary: {survey}"
    );
    let main = reply(&steps, 6);
    assert_eq!(text(&main, "/data/name"), Some("main"), "{main}");
    let puts = reply(&steps, 7);
    assert_eq!(
        text(&puts, "/data/items/0/from_func/name"),
        Some("main"),
        "main calls puts: {puts}"
    );
    let run = reply(&steps, 8);
    assert_eq!(text(&run, "/data/state"), Some("complete"), "{run}");
    let history = reply(&steps, 9);
    assert_eq!(
        history.pointer("/result/structuredContent/ok"),
        Some(&Value::Bool(true)),
        "{history}"
    );
    let undo = reply(&steps, 10);
    assert_eq!(
        text(&undo, "/error/code"),
        Some("NOTHING_TO_UNDO"),
        "the analysis commits are not undo steps: {undo}"
    );
    let decomp = reply(&steps, 11);
    assert!(
        text(&decomp, "/data/decomp/text").is_some_and(|t| t.contains("main(")),
        "func_get include decomp gives the C text of main: {decomp}"
    );
}
