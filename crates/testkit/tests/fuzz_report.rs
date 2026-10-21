//! A long run batch writes its count of passed cases to the report file (AC-190b).
//!
//! The test runs this binary again as a child. The child test runs one fuzz run.

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::path::{Path, PathBuf};
use std::process::Command;

use ghidorah_testkit::fuzz::{self, Config, Outcome, REPORT_ENV, SEED_ENV};

/// The child runs only when the parent sets this variable.
const CHILD_ENV: &str = "GHIDORAH_TESTKIT_REPORT_CHILD";

/// The number of cases of the child run.
const CASES: u32 = 64;

/// Runs the child test with the report file `report`, and with a batch seed when `seed` is
/// `true`.
fn run_child(report: &Path, seed: bool) {
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("current_exe: {e}"));
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", "report_child", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .env(REPORT_ENV, report);
    if seed {
        cmd.env(SEED_ENV, "7");
    } else {
        cmd.env_remove(SEED_ENV);
    }
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("spawn the child: {e}"));
    assert!(
        out.status.success(),
        "the child passes: {:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn regress_long_run_writes_passed_cases() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fuzz_report");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("make {}: {e}", dir.display()));
    let report = dir.join("batch.passed");
    run_child(&report, true);
    let text = std::fs::read_to_string(&report)
        .unwrap_or_else(|e| panic!("the report {} exists: {e}", report.display()));
    assert_eq!(text, format!("{CASES}\n"), "every case of the batch passes");

    // A run without a batch seed does not read the report variable.
    let other = dir.join("tier1.passed");
    run_child(&other, false);
    assert!(!other.exists(), "a tier-1 run writes no report");
}

/// The child test. It does nothing unless the parent sets [`CHILD_ENV`].
#[test]
fn report_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    let config = Config::new("report", CASES);
    let report = fuzz::run(&config, &[vec![1, 2, 3]], |_| Outcome::reached(0))
        .unwrap_or_else(|e| panic!("the run fails: {e}"));
    assert_eq!(report.cases, CASES);
}
