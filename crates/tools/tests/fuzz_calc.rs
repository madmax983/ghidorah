//! Fuzz target `calc` (design Section 13.5, AC-158c).
//!
//! This binary has one test, so the global panic hook has no race. Each case runs the
//! expression engine with the resolver of the demo binary, then the `calc` tool through the
//! dispatcher. A case with `INTERNAL_ERROR` or with two different values is a violation.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use ghidorah_base::FixedClock;
use ghidorah_json::Value;
use ghidorah_testkit::fuzz::{self, Config, Outcome};
use ghidorah_tools::resolve::{Site, resolve_text, value_of};
use ghidorah_tools::{
    Registry, Request, Roots, Session, SessionConfig, ToolSpec, dispatch_with, handlers,
};

/// Stage 0: any input. Stage 1: UTF-8. Stage 2: the syntax is valid. Stage 3: a value.
const STAGES: [&str; 4] = ["input", "utf8", "syntax", "value"];

/// The seed expressions: every operator, every term kind and the error forms.
const SEEDS: [&str; 24] = [
    "0x10 + 0x20",
    "0x10 - 0x20 * 0x3",
    "(0x401000 & ~0xfff) >> 0x4",
    "0x1 << 0x40",
    "0x64 / 0x7 % 0x3",
    "0xf0 | 0x0f ^ 0x3c",
    "-~+0x5",
    "((((0x1))))",
    "main",
    "main+0x10",
    "check_password - main",
    ".text + 0x4",
    "sec:16:.text",
    "seg:3",
    "file:0x1084",
    "imp:puts",
    "FUN_00001234",
    "main@0x1080",
    "0x10 + 16",
    "0x1 / 0x0",
    "0xzz",
    "(0x1",
    "sym:main",
    "fn:0x1080+0x4",
];

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/calc")
}

static TOOLS: &[&ToolSpec<Session>] = &[&handlers::load::SPEC, &handlers::calc::SPEC];

fn demo_session() -> Session {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots = Roots::new(&root, &[PathBuf::from(".")]).expect("the root");
    let mut session = Session::with_registry(
        Registry::new(TOOLS),
        SessionConfig::new(roots),
        Box::new(FixedClock::new(0)),
    );
    let args = ghidorah_json::parse(r#"{"builtin":"demo"}"#, &ghidorah_json::Limits::DEFAULT)
        .expect("the args");
    let envelope = dispatch_with(
        &Registry::new(TOOLS),
        &mut session,
        &Request::new("binary_load", args),
    );
    assert!(envelope.ok(), "the demo loads");
    session
}

fn target(session: &Mutex<Session>, input: &[u8]) -> Outcome {
    let text = String::from_utf8_lossy(input);
    let stage_utf8 = usize::from(std::str::from_utf8(input).is_ok());
    let mut session = session.lock().unwrap_or_else(PoisonError::into_inner);
    let direct = {
        let binary = session.binaries().next().expect("the demo is open");
        let program = &binary.program;
        let mut term = |name: &str| {
            let resolved = resolve_text(program, name, &Site::default())?;
            value_of(program, &resolved).map(|a| a.off)
        };
        ghidorah_tools::calc::eval(&text, &mut term)
    };
    let request = Request::new(
        "calc",
        Value::object([("expr", Value::from(text.as_ref()))]),
    );
    let envelope = dispatch_with(&Registry::new(TOOLS), &mut session, &request).to_json();
    let error = envelope.pointer("/error/code").and_then(Value::as_str);
    if error == Some("INTERNAL_ERROR") {
        return Outcome::violation(stage_utf8, "calc gives INTERNAL_ERROR".to_owned());
    }
    match direct {
        Ok(value) => {
            let shown = envelope.pointer("/data/value").and_then(Value::as_str);
            let long = text.chars().count() > ghidorah_tools::calc::MAX_EXPR_CHARS;
            if !long && shown != Some(format!("{value:#x}").as_str()) {
                return Outcome::violation(3, format!("the tool gives {shown:?} for {value:#x}"));
            }
            Outcome::reached(3)
        }
        Err(e) if e.code == ghidorah_base::ErrorCode::InvalidArgument => {
            Outcome::reached(stage_utf8)
        }
        Err(_) => Outcome::reached(2),
    }
}

#[test]
fn fuzz_calc() {
    let session = Mutex::new(demo_session());
    let run = |input: &[u8]| target(&session, input);
    let replay = fuzz::replay_regress(&regress_dir(), run)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let corpus: Vec<Vec<u8>> = SEEDS.iter().map(|s| s.as_bytes().to_vec()).collect();
    let mut config = Config::new("calc", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 256;
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
    assert!(
        report.reached_percent(2) >= 10,
        "syntax share: {:?}",
        report.reached
    );
    assert!(report.reached[3] > 0, "value share: {:?}", report.reached);
}
