//! The `xtask fuzz` command: long runs of every fuzz target of design Section 13.5 (AC-190b).
//!
//! Each target is one test binary `crates/<crate>/tests/fuzz_<target>.rs` with one test
//! function. One batch is one run of that binary in a child process with the variable
//! `FUZZ_SEED`. The harness of `testkit::fuzz` mixes the batch seed into its fixed seed, so
//! each batch runs new cases. A wall-clock watchdog stops a batch that hangs.
//!
//! After a failed batch, the command moves each failing input to
//! `tests/regress/<target>/<sha8>.bin`. The harness shrinks a panic or a violation before it
//! saves the input. A `pending.bin` from an abort, a stack overflow or a hang keeps its bytes.
//! Every later test run replays the regression files.
//!
//! Output: `{ ok, iters, seed, violations, targets: { <target>: { batches, cases, failed,
//! hangs, saved } } }`. AC-190b reads `/violations`.

use std::path::{Path, PathBuf};

use crate::json::Value;
use crate::{Error, Finding};

/// One fuzz target of design Section 13.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    /// The target name, for example `elf_load`.
    pub name: &'static str,
    /// The package directory, for example `crates/loader`.
    pub dir: &'static str,
    /// The package name, for example `ghidorah-loader`.
    pub package: &'static str,
    /// The number of cases of one tier-1 run, and so of one batch.
    pub cases: u32,
}

/// The fuzz targets of design Section 13.5.
pub const TARGETS: &[Target] = &[];

/// The default number of cases of each target (design Section 13.5).
pub const DEFAULT_ITERS: u64 = 100_000;

/// The default watchdog limit of one batch in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 900;

/// The largest number of failed batches of one target. Later batches do not run.
pub const MAX_FAILED_BATCHES: u64 = 3;

/// The parsed command line of `xtask fuzz`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The targets to run, in table order.
    pub targets: Vec<&'static Target>,
    /// The number of cases of each target.
    pub iters: u64,
    /// The seed of the first batch.
    pub seed: u64,
    /// The watchdog limit of one batch in seconds.
    pub timeout_secs: u64,
}

/// Parses `[<target>..] [--iters N] [--seed S] [--timeout SECS]`.
///
/// # Errors
///
/// Returns [`Error::Usage`] for an unknown flag, a bad number or an unknown target.
pub fn parse_args(args: &[String]) -> Result<Options, Error> {
    let _ = args;
    Err(Error::Usage("cargo xtask fuzz".to_owned()))
}

/// Gives the number of batches of `iters` cases for a target with `cases` cases per batch.
#[must_use]
pub const fn batches(iters: u64, cases: u32) -> u64 {
    let _ = (iters, cases);
    0
}

/// Gives the `FUZZ_SEED` value of batch `batch` of a run with the seed `seed`.
#[must_use]
pub const fn batch_seed(seed: u64, batch: u64) -> u64 {
    let _ = batch;
    seed
}

/// Gives the regression file name of an input: the first 8 hex digits of its SHA-256 and
/// `.bin`.
#[must_use]
pub fn regress_name(bytes: &[u8]) -> String {
    let _ = bytes;
    String::new()
}

/// Gives the test file of `target`, relative to the workspace root.
#[must_use]
pub fn test_file(target: &Target) -> String {
    format!("{}/tests/fuzz_{}.rs", target.dir, target.name)
}

/// Checks the source text of the test file of `target`. Gives one message per problem.
///
/// The file has one `#[test]` function `fuzz_<target>`. It replays the regression files of
/// `tests/regress/<target>`, and its configuration has at least the cases of the table.
#[must_use]
pub fn source_problems(target: &Target, text: &str) -> Vec<String> {
    let _ = (target, text);
    Vec::new()
}

/// AC-190a: checks the test file of every target. Gives one finding per problem.
#[must_use]
pub fn check_targets(root: &Path) -> Vec<Finding> {
    let _ = root;
    Vec::new()
}

/// Gives the regression directory of `target`.
#[must_use]
pub fn regress_dir(root: &Path, target: &Target) -> PathBuf {
    root.join("tests/regress").join(target.name)
}

/// Moves the failing inputs of a batch in `dir` to `<sha8>.bin` files. Gives the new names.
///
/// The inputs are the `crash-<case>.input` files of the harness and a left `pending.bin`.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file does not read, write or move.
pub fn collect(dir: &Path) -> Result<Vec<String>, Error> {
    let _ = dir;
    Ok(Vec::new())
}

/// Runs `xtask fuzz`.
///
/// # Errors
///
/// Returns an error for a bad command line, a build that fails or a process that does not
/// start.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let _ = (root, args);
    Err(Error::Usage("cargo xtask fuzz".to_owned()))
}
