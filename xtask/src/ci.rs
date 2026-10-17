//! The `xtask ci` command: the CI steps of both tiers and the time of each test.
//!
//! Output: `{ ok, steps: { <step>: { ok, seconds, .. } } }`.
//! AC-002 reads `/steps/offline_build/ok`. AC-021 reads `/steps/tier1/seconds`.
//! AC-224 reads `/steps/test_times/max_seconds`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Error;
use crate::json::Value;

/// The time cap of one tier-1 test in milliseconds (AC-224).
pub const TEST_CAP_MS: u64 = 15_000;

/// One step of `xtask ci`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// `cargo fmt --all -- --check`.
    Fmt,
    /// `cargo clippy --workspace --all-targets -- -D warnings`.
    Clippy,
    /// `cargo doc --workspace --no-deps` with `RUSTDOCFLAGS=-Dwarnings`.
    Doc,
    /// An offline build with an empty `CARGO_HOME` (AC-002).
    OfflineBuild,
    /// `cargo test --workspace` (tier 1).
    Tier1,
    /// `cargo test --workspace -- --include-ignored` (tier 2).
    Tier2,
    /// A run with one test thread that records the time of each test.
    TestTimes,
}

impl Step {
    /// The steps of a run without `--steps` and without `--tier2`.
    pub const DEFAULT: &[Self] = &[
        Self::Fmt,
        Self::Clippy,
        Self::Doc,
        Self::OfflineBuild,
        Self::Tier1,
        Self::TestTimes,
    ];

    /// Gives the step name of the JSON output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fmt => "fmt",
            Self::Clippy => "clippy",
            Self::Doc => "doc",
            Self::OfflineBuild => "offline_build",
            Self::Tier1 => "tier1",
            Self::Tier2 => "tier2",
            Self::TestTimes => "test_times",
        }
    }

    /// Gives the step of a name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let _ = name;
        None
    }
}

/// The parsed command line of `xtask ci`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The steps to run, in order.
    pub steps: Vec<Step>,
    /// True when tier-2 tests also run (`--tier2`).
    pub tier2: bool,
}

/// Parses `[--tier2] [--steps a,b,..]`.
///
/// # Errors
///
/// Returns [`Error::Usage`] for an unknown flag or step.
pub fn parse_args(args: &[String]) -> Result<Options, Error> {
    let _ = args;
    Err(Error::Usage("ci".to_owned()))
}

/// The empty cargo home of the offline build step.
#[must_use]
pub fn offline_home(root: &Path) -> PathBuf {
    root.join("target").join("xtask-ci").join("cargo-home")
}

/// Gives the command of a step.
#[must_use]
pub fn command(root: &Path, step: Step, tier2: bool) -> Command {
    let _ = (root, step, tier2);
    Command::new("false")
}

/// The time of one test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestTime {
    /// The index of the test binary in the run, from 0.
    pub binary: usize,
    /// The test name.
    pub name: String,
    /// The time in milliseconds.
    pub ms: u64,
    /// True when the test passed or was ignored.
    pub ok: bool,
}

/// Gives the time of each test from timed libtest output lines.
///
/// Each line comes with its arrival time in milliseconds. The run uses one test thread,
/// so the time of a test is the gap since the line before it.
#[must_use]
pub fn parse_test_times(lines: &[(u64, String)]) -> Vec<TestTime> {
    let _ = lines;
    Vec::new()
}

/// Runs `xtask ci`.
///
/// # Errors
///
/// Returns an error for a bad command line or a process that does not start.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let _ = (root, args);
    Err(Error::Usage("ci".to_owned()))
}
