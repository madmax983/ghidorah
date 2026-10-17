//! Fuzz target `snapshot_load` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race. Each case decodes the input
//! as a snapshot and restores it into a fresh program. A case gives a snapshot error or a
//! program, and never a panic. A failed restore changes nothing.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

use std::path::PathBuf;

use ghidorah_base::Limits;
use ghidorah_db::{Program, snapshot};
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::fuzz::{self, Config, Outcome};

/// Stage 0: any input. Stage 1: the snapshot decodes. Stage 2: the snapshot restores.
const STAGES: [&str; 3] = ["input", "decoded", "restored"];

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/snapshot_load")
}

fn program() -> Program {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/bin/crackme.gcc-O2");
    let bytes = std::fs::read(path).expect("the fixture");
    let (binary, mem) = load(&bytes, &LoadOpts::AUTO, &Limits::DEFAULT).expect("the load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("the program")
}

fn target(start: &Program, input: &[u8]) -> Outcome {
    let Ok(snap) = snapshot::decode(input) else {
        return Outcome::reached(0);
    };
    let mut p = start.clone();
    match snap.restore(&mut p) {
        Ok(()) => Outcome::reached(2),
        Err(_) if p.state_hash() == start.state_hash() => Outcome::reached(1),
        Err(e) => Outcome::violation(1, format!("a failed restore changes the program: {e}")),
    }
}

#[test]
fn fuzz_snapshot_load() {
    let start = program();
    let text = snapshot::encode(&start, 0, None).expect("the snapshot");
    let corpus = vec![text.into_bytes()];
    let run = |input: &[u8]| target(&start, input);
    let replay = fuzz::replay_regress(&regress_dir(), run)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);
    let mut config = Config::new("snapshot_load", 300);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 262_144;
    config.stack_size = 8 * 1024 * 1024;
    let report =
        fuzz::run(&config, &corpus, run).unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 300);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report.crashes
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    assert!(report.reached[1] > 0, "decode share: {:?}", report.reached);
}
