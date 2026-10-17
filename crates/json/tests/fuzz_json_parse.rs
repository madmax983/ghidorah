//! Fuzz target `json_parse` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race.
//! The seeds are the vendored JSONTestSuite files. Each case runs in a 256 KiB stack.

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod common;

use std::path::PathBuf;

use ghidorah_json::pointer;
use ghidorah_json::{Limits, Value, parse, parse_bytes, write, write_jcs, write_pretty};
use ghidorah_testkit::fuzz::{self, Config, Outcome};

/// Stage 0: any input. Stage 1: the input parses. Stage 2: the value is an array or an object.
const STAGES: [&str; 3] = ["input", "parsed", "container"];

/// The regression directory of the target: `tests/regress/json_parse/`.
fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/json_parse")
}

fn corpus() -> Vec<Vec<u8>> {
    let dir = common::suite_dir();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files
        .iter()
        .filter_map(|p| std::fs::read(p).ok())
        .filter(|b| b.len() <= 4096)
        .collect()
}

/// Checks the properties of one parsed value.
fn check_value(value: &Value, limits: &Limits) -> Result<(), String> {
    let text = write(value);
    if parse(&text, limits).as_ref() != Ok(value) {
        return Err(format!("write then parse differs: {text}"));
    }
    let pretty = write_pretty(value);
    if parse(&pretty, limits).as_ref() != Ok(value) {
        return Err(format!("pretty write then parse differs: {pretty}"));
    }
    if let Ok(jcs) = write_jcs(value) {
        let back = parse(&jcs, limits).map_err(|e| format!("JCS text {jcs} fails: {e}"))?;
        if write_jcs(&back).as_deref() != Ok(jcs.as_str()) {
            return Err(format!("JCS is not stable: {jcs}"));
        }
    }
    for text in ["/*", "/*/*", "/0", "/a", ""] {
        if let Ok(ptr) = pointer::parse(text) {
            let selection = pointer::select(value, &ptr);
            if !ptr.has_star() && selection.values.first().copied() != pointer::get(value, &ptr) {
                return Err(format!("select and get differ at {text}"));
            }
        }
    }
    Ok(())
}

fn target(input: &[u8]) -> Outcome {
    let limits = Limits::DEFAULT;
    match parse_bytes(input, &limits) {
        Err(e) if e.offset > input.len() => {
            Outcome::violation(0, format!("offset {} after the end", e.offset))
        }
        Err(_) => Outcome::reached(0),
        Ok(value) => {
            let stage = if matches!(value, Value::Array(_) | Value::Object(_)) {
                2
            } else {
                1
            };
            match check_value(&value, &limits) {
                Ok(()) => Outcome::reached(stage),
                Err(message) => Outcome::violation(stage, message),
            }
        }
    }
}

#[test]
fn fuzz_json_parse() {
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new("json_parse", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    let report = fuzz::run(&config, &corpus(), target)
        .unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
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
        "parsed share: {:?}",
        report.reached
    );
    assert!(
        report.reached_percent(2) >= 5,
        "container share: {:?}",
        report.reached
    );
}
