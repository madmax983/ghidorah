//! Fuzz target `cursor_decode` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race. Each case decodes the input
//! as cursor text and as cursor bytes. A decode gives a key, `CURSOR_INVALID` or
//! `CURSOR_STALE`, and never another code. A decoded cursor encodes to the same key again.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

use std::path::PathBuf;

use ghidorah_base::ErrorCode;
use ghidorah_testkit::fuzz::{self, Config, Outcome};
use ghidorah_tools::args::parse;
use ghidorah_tools::cursor::{Cursor, Spill, decode, encode};
use ghidorah_tools::dispatch::CursorCall;
use ghidorah_tools::{AnalysisInfo, AnalysisState, Args, Frame, KeyPart, SortKey, handlers};

/// Stage 0: any input. Stage 1: hex text. Stage 2: the check passes. Stage 3: a key.
const STAGES: [&str; 4] = ["input", "hex", "checked", "key"];

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/cursor_decode")
}

fn args() -> Args {
    let raw = ghidorah_json::parse(r#"{"query":"load"}"#, &ghidorah_json::Limits::DEFAULT)
        .expect("the args");
    parse(&handlers::tool_search::SPEC, &raw, None)
        .expect("the args parse")
        .args
}

fn frame() -> Frame {
    Frame {
        binary_id: Some("467a43b75d95c826".to_owned()),
        rev: 1,
        session: "fuzz".to_owned(),
        analysis: Some(AnalysisInfo {
            state: AnalysisState::Complete,
            rev: 1,
        }),
    }
}

fn target(call: &CursorCall<'_>, spill: &Spill, input: &[u8]) -> Outcome {
    // The byte form must never panic. A cursor that reads must write the same bytes again.
    if let Ok(cursor) = Cursor::from_bytes(input, spill) {
        let mut store = spill.clone();
        let again = Cursor::from_bytes(&cursor.to_bytes(&mut store), &store);
        if again.as_ref().ok() != Some(&cursor) {
            return Outcome::violation(2, "the bytes do not round-trip".to_owned());
        }
    }
    let text = String::from_utf8_lossy(input);
    let hex = !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit());
    match decode(call, &text, 0, spill) {
        Ok(key) => {
            let mut store = spill.clone();
            let back = encode(call, &key, 0, &mut store);
            match decode(call, &back, 0, &store) {
                Ok(again) if again == key => Outcome::reached(3),
                other => Outcome::violation(3, format!("the key does not round-trip: {other:?}")),
            }
        }
        Err(e) if e.code == ErrorCode::CursorStale => Outcome::reached(2),
        Err(e) if e.code == ErrorCode::CursorInvalid => Outcome::reached(usize::from(hex)),
        Err(e) => Outcome::violation(1, format!("the decode gives {}", e.code)),
    }
}

#[test]
fn fuzz_cursor_decode() {
    let args = args();
    let frame = frame();
    let call = CursorCall {
        tool_index: 2,
        tool: "tool_search",
        args: &args,
        frame: &frame,
    };
    let mut spill = Spill::new();
    let keys = [
        SortKey(vec![KeyPart::Int(0x40_1000)]),
        SortKey(vec![KeyPart::Text("main".to_owned()), KeyPart::Int(0x1080)]),
        SortKey(vec![
            KeyPart::Int(3),
            KeyPart::Int(0x1080),
            KeyPart::Text("fn:0x1080".to_owned()),
        ]),
        SortKey(Vec::new()),
        SortKey(vec![KeyPart::Text("x".repeat(2_000))]),
    ];
    let corpus: Vec<Vec<u8>> = keys
        .iter()
        .map(|k| encode(&call, k, 0, &mut spill).into_bytes())
        .collect();
    let run = |input: &[u8]| target(&call, &spill, input);
    let replay = fuzz::replay_regress(&regress_dir(), run)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new("cursor_decode", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 1_100;
    let report =
        fuzz::run(&config, &corpus, run).unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 2000);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report.crashes
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    assert!(report.reached[1] > 0, "hex share: {:?}", report.reached);
}
