//! Fuzz target `project_json` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race. Each case reads the input as
//! a project file. A case gives a project file or `BadMeta`, and never a panic. A project file
//! that reads writes the same JSON again.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

use std::path::PathBuf;

use ghidorah_base::Limits;
use ghidorah_db::{LoadSpec, Program, ProjectMeta};
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::fuzz::{self, Config, Outcome};

/// Stage 0: any input. Stage 1: JSON. Stage 2: a project file.
const STAGES: [&str; 3] = ["input", "json", "project"];

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/project_json")
}

fn corpus() -> Vec<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/bin/crackme.gcc-O2");
    let bytes = std::fs::read(path).expect("the fixture");
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("the load");
    let program = Program::from_binary(binary, mem, &Limits::DEFAULT).expect("the program");
    let auto = ProjectMeta::new(&program, "crackme", LoadSpec::Auto);
    let raw = ProjectMeta::new(
        &program,
        "blob.bin",
        LoadSpec::Raw {
            base: 0x40_0000,
            entry: None,
        },
    );
    [auto, raw]
        .iter()
        .map(|m| ghidorah_json::write(&m.to_json()).into_bytes())
        .collect()
}

fn target(input: &[u8]) -> Outcome {
    let Ok(text) = std::str::from_utf8(input) else {
        return Outcome::reached(0);
    };
    let Ok(value) = ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT) else {
        return Outcome::reached(0);
    };
    match ProjectMeta::from_json(&value) {
        Ok(meta) => match ProjectMeta::from_json(&meta.to_json()) {
            Ok(again) if again == meta => Outcome::reached(2),
            _ => Outcome::violation(2, "the project file does not round-trip".to_owned()),
        },
        Err(_) => Outcome::reached(1),
    }
}

#[test]
fn fuzz_project_json() {
    let corpus = corpus();
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);
    let mut config = Config::new("project_json", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 2_048;
    let report = fuzz::run(&config, &corpus, target)
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
    assert!(report.reached[2] > 0, "project share: {:?}", report.reached);
}
