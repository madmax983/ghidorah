//! The `xtask cov` command: line coverage with rustup `llvm-tools` (ADR-0027).
//!
//! Output: `{ ok, workspace: {..}, crates: { <dir>: {..} }, objects, tests_ok }`.
//! Percent values are integers in hundredths (`percent_x100`), so the output has no floats.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::Error;
use crate::json::Value;

/// The minimum line coverage of the workspace in percent (AC-013).
pub const WORKSPACE_MIN: u64 = 85;

/// The minimum line coverage of each core crate in percent (AC-013).
pub const CORE_MIN: u64 = 90;

/// The minimum line coverage of `ghidorah-kernel` in percent (AC-013).
pub const KERNEL_MIN: u64 = 95;

/// The core crates of AC-013, as directory names under `crates/`.
pub const CORE: &[&str] = &["json", "loader", "x86", "ir", "db", "analysis", "tools"];

/// The dev crates that the measurement leaves out, as directory names under `crates/`.
pub const DEV_DIRS: &[&str] = &["testkit", "oracle", "eval"];

/// Line and region counts of one crate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Instrumented lines.
    pub lines: u64,
    /// Lines that ran at least once.
    pub covered: u64,
    /// Instrumented regions.
    pub regions: u64,
    /// Regions that ran at least once.
    pub regions_covered: u64,
}

/// The counts of each measured crate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    /// The counts by crate directory name.
    pub crates: BTreeMap<String, Counts>,
}

/// Gives the minimum line coverage of one crate, or `None` when only the workspace line applies.
#[must_use]
pub fn min_percent(dir: &str) -> Option<u64> {
    let _ = dir;
    None
}

/// Gives the crate directory of a measured source file, or `None` when the file is out of scope.
///
/// Out of scope: files outside `crates/*/src`, `tests.rs` files, `tests/` directories and dev crates.
#[must_use]
pub fn crate_of(rel: &str) -> Option<&str> {
    let _ = rel;
    None
}

/// Sums the per-file totals of `llvm-cov export --summary-only` by crate.
///
/// # Errors
///
/// Returns [`Error::Data`] when the export has a bad form.
pub fn summarize(root: &Path, export: &Value) -> Result<Coverage, Error> {
    let _ = (root, export);
    Err(Error::data("llvm-cov export", "summary missing"))
}

/// Applies the thresholds and gives the JSON report with its `ok` member.
#[must_use]
pub fn gate(coverage: &Coverage) -> Value {
    let _ = coverage;
    Value::object([("ok", Value::from(false))])
}

/// Gives the executables of `cargo test --no-run --message-format=json` output.
#[must_use]
pub fn test_objects(cargo_json: &str) -> Vec<PathBuf> {
    let _ = cargo_json;
    Vec::new()
}

/// Runs `xtask cov`.
///
/// # Errors
///
/// Returns an error when a build, a tool or a file operation fails.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let _ = (root, args);
    Err(Error::Usage("cov".to_owned()))
}
