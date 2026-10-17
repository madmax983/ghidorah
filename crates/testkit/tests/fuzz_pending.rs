//! The pending file survives an abort of the fuzz process.
//!
//! The test runs this binary again as a child. The child test aborts during a case.

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::path::PathBuf;
use std::process::Command;

use ghidorah_testkit::fuzz::{self, Config, Outcome, PENDING_FILE};

/// The child reads the pending directory from this variable.
const CHILD_ENV: &str = "GHIDORAH_TESTKIT_ABORT_CHILD";

/// The parent test reads its pending directory from this variable.
/// Without the variable, it uses a fixed directory.
const DIR_ENV: &str = "GHIDORAH_TESTKIT_ABORT_DIR";

/// The byte that makes the child abort.
const TRIGGER: u8 = 0xab;

fn pending_dir() -> PathBuf {
    std::env::var_os(DIR_ENV).map_or_else(
        || PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fuzz_pending_abort"),
        PathBuf::from,
    )
}

#[test]
fn fuzz_pending_file_survives_abort() {
    let dir = pending_dir();
    let _ = std::fs::remove_dir_all(&dir);
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("current_exe: {e}"));
    // The parent keeps the output of the child, so the libtest output holds no child line.
    let child = Command::new(exe)
        .args(["--exact", "abort_child", "--test-threads=1", "--nocapture"])
        .env(CHILD_ENV, &dir)
        .output()
        .unwrap_or_else(|e| panic!("spawn the child: {e}"));
    assert!(
        !child.status.success(),
        "the child aborts: {:?}\n{}",
        child.status,
        String::from_utf8_lossy(&child.stdout)
    );
    let pending = dir.join(PENDING_FILE);
    let bytes = std::fs::read(&pending)
        .unwrap_or_else(|e| panic!("the pending file {} exists: {e}", pending.display()));
    assert!(
        bytes.contains(&TRIGGER),
        "the pending file holds the abort input"
    );

    // A replay runs the leftover pending input.
    let report = fuzz::replay_regress(&dir, |input| {
        if input.contains(&TRIGGER) {
            Outcome::violation(0, "trigger byte".to_string())
        } else {
            Outcome::reached(0)
        }
    });
    let Ok(report) = report else {
        panic!("replay fails: {report:?}");
    };
    assert_eq!(report.cases, 1);
    assert_eq!(report.violations, 1);
}

#[test]
fn fuzz_pending_file_is_deleted_after_a_normal_run() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fuzz_pending_normal");
    let _ = std::fs::remove_dir_all(&dir);
    let mut config = Config::new("normal", 50);
    config.pending_dir = Some(dir.clone());
    let report = fuzz::run(&config, &[vec![1, 2, 3]], |_| Outcome::reached(0));
    assert_eq!(report.map(|r| r.cases), Ok(50));
    assert!(!dir.join(PENDING_FILE).exists());
}

/// The output of the abort child stays out of the libtest output of the parent test.
///
/// `xtask ci` reads one `test <name> ... <result>` line for each test (AC-224).
#[test]
fn regress_abort_child_output_stays_out_of_the_test_output() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fuzz_pending_regress");
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("current_exe: {e}"));
    let out = Command::new(exe)
        .args([
            "--exact",
            "fuzz_pending_file_survives_abort",
            "--test-threads=1",
        ])
        .env(DIR_ENV, &dir)
        .output()
        .unwrap_or_else(|e| panic!("spawn the parent test: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "the parent test passes:\n{stdout}");
    assert!(
        stdout
            .lines()
            .any(|l| l == "test fuzz_pending_file_survives_abort ... ok"),
        "one result line for the parent test:\n{stdout}"
    );
    assert!(
        !stdout.contains("abort_child"),
        "no line of the abort child:\n{stdout}"
    );
}

/// The child test. It does nothing unless the parent sets [`CHILD_ENV`].
#[test]
fn abort_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let mut config = Config::new("abort", 2000);
    config.pending_dir = Some(PathBuf::from(dir));
    let _ = fuzz::run(&config, &[vec![0, 1, 2, 3]], |input| {
        if input.contains(&TRIGGER) {
            std::process::abort();
        }
        Outcome::reached(0)
    });
}
