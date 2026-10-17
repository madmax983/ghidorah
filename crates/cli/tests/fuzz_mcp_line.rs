//! Fuzz target `mcp_line` (design Section 13.5).
//!
//! Each case frames the input into lines with a cap of 4,096 bytes and sends each line to a
//! new MCP server over the test registry in profile `mini`. No case may panic. Each output line must be one
//! JSON-RPC message, and no tool result may hold `INTERNAL_ERROR`.
//! This binary has one test, so the global panic hook has no race.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(
    clippy::unnecessary_wraps,
    reason = "test handlers have the handler type, which returns a Result"
)]

mod common;

use std::io::Cursor;
use std::path::PathBuf;

use ghidorah_base::FixedClock;
use ghidorah_cli::mcp::frame::LineReader;
use ghidorah_cli::mcp::server::Server;
use ghidorah_cli::{Backend, Env, Options};
use ghidorah_json::{Limits, Value};
use ghidorah_testkit::fuzz::{self, Config, Outcome};
use ghidorah_tools::{ContentMode, Profile};

use crate::common::registry::TestHost;
use crate::common::transcript::{self, ClientLine};

/// Stage 0: any input. Stage 1: a line is JSON. Stage 2: a line is a message.
/// Stage 3: a request gets a result.
const STAGES: [&str; 4] = ["input", "json", "message", "result"];

/// The transcripts whose client lines seed the corpus.
const SEEDS: [&str; 7] = [
    "legacy_2025_11_25",
    "legacy_2025_06_18",
    "legacy_fallback",
    "modern",
    "era_errors",
    "framing",
    "tool_errors",
];

/// The cap of one line in a case.
const CAP: usize = 4096;

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/mcp_line")
}

fn corpus() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for name in SEEDS {
        let lines: Vec<Vec<u8>> = transcript::clients(name)
            .iter()
            .map(ClientLine::bytes)
            .collect();
        out.extend(lines.iter().cloned());
        out.push(lines.join(&b'\n'));
    }
    out.push(
        br#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"item_list","arguments":{"count":3},"_meta":{"progressToken":"p","io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#
            .to_vec(),
    );
    out
}

/// Checks one output line. Gives `true` for a reply with a result.
fn check_line(line: &str) -> Result<bool, String> {
    let value = ghidorah_json::parse(line, &Limits::DEFAULT)
        .map_err(|e| format!("the output is not JSON: {e}: {line}"))?;
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(format!("no jsonrpc member: {line}"));
    }
    let reply = value.get("id").is_some()
        && (value.get("result").is_some() != value.get("error").is_some());
    let note = value.get("id").is_none() && value.get("method").is_some();
    if !reply && !note {
        return Err(format!("not one JSON-RPC message: {line}"));
    }
    if line.contains("\"INTERNAL_ERROR\"") {
        return Err(format!("a tool panicked: {line}"));
    }
    Ok(value.get("result").is_some())
}

fn target(input: &[u8]) -> Outcome {
    // The profile `mini` leaves out `wait_cancel`, so no case waits.
    let mut options = Options::new(&Env::new(PathBuf::from("/fuzz")), "mcp-1");
    options.profile = Profile::Mini;
    let Ok(host) = TestHost::open(&options) else {
        return Outcome::violation(0, "the test host does not open".to_owned());
    };
    let mut server = Server::new(host, ContentMode::Both, Box::new(FixedClock::new(0)));
    let mut reader = LineReader::new(Cursor::new(input), CAP);
    let mut stage = 0;
    while let Ok(Some(frame)) = reader.next_frame() {
        if let ghidorah_cli::mcp::frame::Frame::Line(bytes) = &frame
            && let Ok(value) = ghidorah_json::parse_bytes(bytes, &Limits::DEFAULT)
        {
            stage = stage.max(1);
            if value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
                && (value.get("method").is_some() || value.get("result").is_some())
            {
                stage = stage.max(2);
            }
        }
        for line in server.handle_frame(&frame) {
            match check_line(&line) {
                Ok(true) => stage = 3,
                Ok(false) => {}
                Err(message) => return Outcome::violation(stage, message),
            }
        }
    }
    Outcome::reached(stage)
}

#[test]
fn fuzz_mcp_line() {
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new("mcp_line", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    let report =
        fuzz::run(&config, &corpus(), target).unwrap_or_else(|e| panic!("the fuzz harness: {e}"));
    assert_eq!(report.cases, 2000);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report.crashes
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    assert!(
        report.reached_percent(1) >= 10,
        "json share: {:?}",
        report.reached
    );
    assert!(
        report.reached_percent(2) >= 5,
        "message share: {:?}",
        report.reached
    );
    assert!(report.reached[3] > 0, "result count: {:?}", report.reached);
}
