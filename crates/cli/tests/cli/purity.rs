//! stdout purity: protocol lines only, logs on stderr (AC-170).

use ghidorah_cli::mcp::{ServeOptions, serve};
use ghidorah_cli::{Exit, Options};
use ghidorah_json::Value;

use crate::common::registry::TestHost;
use crate::common::{env, json, run_binary, streams};

/// The client lines: handshakes, faults, notifications and tool calls.
const LINES: &[&str] = &[
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    "garbage line",
    "[]",
    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
    r#"{"jsonrpc":"2.0","id":4,"method":"server/discover"}"#,
    r#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#,
    r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"echo_text","arguments":{"text":"line\nbreak"}}}"#,
];

/// Checks that each line is one JSON-RPC message. Gives the messages.
fn messages(stdout: &str) -> Vec<Value> {
    assert!(stdout.ends_with('\n'), "each line ends with a line end");
    stdout
        .lines()
        .map(|line| {
            let value = json(line);
            assert_eq!(value.get("jsonrpc"), Some(&json(r#""2.0""#)), "{line}");
            let reply = value.get("id").is_some()
                && (value.get("result").is_some() != value.get("error").is_some());
            let note = value.get("id").is_none() && value.get("method").is_some();
            assert!(reply || note, "one JSON-RPC message: {line}");
            value
        })
        .collect()
}

#[test]
fn ac_170_stdout_purity() {
    let input: String = LINES.iter().map(|l| format!("{l}\n")).collect();
    let output = run_binary(&["mcp"], &input);
    assert_eq!(output.code, 0, "{}", output.stderr);
    let replies = messages(&output.stdout);
    assert_eq!(replies.len(), 8, "{}", output.stdout);
    assert!(!output.stderr.is_empty(), "the server logs to stderr");
    for line in output.stderr.lines() {
        assert!(line.starts_with("ghidorah"), "a log line: {line}");
        assert!(ghidorah_json::parse(line, &ghidorah_json::Limits::DEFAULT).is_err());
    }

    let (streams, out, err) = streams(input.as_bytes());
    let options = Options::new(&env("purity"), "mcp-1");
    let exit = serve::<TestHost>(options, &ServeOptions::default(), streams);
    assert_eq!(exit, Exit::Ok);
    let replies = messages(&out.text());
    assert_eq!(replies.len(), 8);
    let echo = replies.last().expect("the echo reply");
    assert_eq!(
        echo.pointer("/result/structuredContent/data/text"),
        Some(&json(r#""line\nbreak""#))
    );
    assert!(!err.text().is_empty(), "the server logs to stderr");
}
