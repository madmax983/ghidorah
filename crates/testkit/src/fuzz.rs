//! A std-only fuzz harness.
//!
//! [`mutate`] applies AFL-style havoc steps. [`run`] runs fixed-seed cases in a
//! thread with a small stack. Before each case it writes the input to
//! `pending.bin`, and after the case it deletes the file. An abort, a stack
//! overflow or a hang leaves the file, so the next run can replay it.
//!
//! Each case returns the deepest stage that it reached. The report counts the
//! cases per stage. A panic hook counts every panic in the test binary, also
//! the panics that a target catches. Put each fuzz target in its own test binary.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::rng::Xoshiro256ss;

/// The file name of the input of the running case.
pub const PENDING_FILE: &str = "pending.bin";

/// The default stack size of the case thread (256 KiB).
pub const DEFAULT_STACK: usize = 256 * 1024;

/// The default largest input length.
pub const DEFAULT_MAX_LEN: usize = 4096;

/// The settings of one fuzz run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The target name.
    pub target: String,
    /// The number of cases.
    pub cases: u32,
    /// The seed of the mutation generator.
    pub seed: u64,
    /// The largest input length.
    pub max_len: usize,
    /// The stack size of the case thread.
    pub stack_size: usize,
    /// The directory of `pending.bin`. `None` writes no pending file.
    pub pending_dir: Option<PathBuf>,
    /// The stage names, from the first stage to the deepest stage.
    pub stages: Vec<String>,
    /// The largest number of crashes that the report keeps.
    pub max_crashes: usize,
}

impl Config {
    /// Makes the default settings for `target` with `cases` cases.
    ///
    /// The seed is the FNV-1a hash of the target name.
    #[must_use]
    pub fn new(target: &str, cases: u32) -> Self {
        Self {
            target: target.to_string(),
            cases,
            seed: 0,
            max_len: DEFAULT_MAX_LEN,
            stack_size: DEFAULT_STACK,
            pending_dir: None,
            stages: Vec::new(),
            max_crashes: 16,
        }
    }
}

/// The result of one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The index of the deepest stage that the case reached.
    pub stage: usize,
    /// A broken target property, if the case found one.
    pub violation: Option<String>,
}

impl Outcome {
    /// Makes an outcome with no violation.
    #[must_use]
    pub const fn reached(stage: usize) -> Self {
        Self {
            stage,
            violation: None,
        }
    }

    /// Makes an outcome with a violation.
    #[must_use]
    pub const fn violation(stage: usize, message: String) -> Self {
        Self {
            stage,
            violation: Some(message),
        }
    }
}

/// One failed case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crash {
    /// The case index.
    pub case: u32,
    /// The input of the case.
    pub input: Vec<u8>,
    /// The panic message or the violation message.
    pub message: String,
}

/// The result of a fuzz run or a replay.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// The target name.
    pub target: String,
    /// The number of cases that ran.
    pub cases: u32,
    /// The number of cases that panicked.
    pub panics: u64,
    /// The number of cases that gave a violation.
    pub violations: u64,
    /// The first failed cases, at most `max_crashes`.
    pub crashes: Vec<Crash>,
    /// For each stage index `k`, the number of cases whose deepest stage is `k` or more.
    pub reached: Vec<u64>,
}

impl Report {
    /// Returns `true` when no case panicked and no case gave a violation.
    #[must_use]
    pub const fn ok(&self) -> bool {
        false
    }

    /// Returns the share of cases that reached `stage`, in percent (0 to 100).
    #[must_use]
    pub fn reached_percent(&self, stage: usize) -> u64 {
        let _ = stage;
        0
    }
}

/// An error of the fuzz harness itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzError {
    /// A file operation failed.
    Io {
        /// The file or directory.
        path: String,
        /// The operating system message.
        message: String,
    },
    /// The case thread did not start or did not join.
    Thread(String),
}

impl fmt::Display for FuzzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(f, "fuzz file error at {path}: {message}"),
            Self::Thread(message) => write!(f, "fuzz thread error: {message}"),
        }
    }
}

impl std::error::Error for FuzzError {}

/// Applies 2 to 16 random havoc steps to `input`.
///
/// The steps are: bit flip, random byte, interesting value, add or subtract
/// 1 to 35, delete block and insert byte. The result has at most `max_len` bytes.
pub fn mutate(rng: &mut Xoshiro256ss, input: &[u8], max_len: usize) -> Vec<u8> {
    let _ = (rng, max_len);
    input.to_vec()
}

/// Runs the cases of `config` against `target`.
///
/// Each case takes a corpus input (or an empty input) and mutates it.
///
/// # Errors
///
/// Returns [`FuzzError`] when the pending file or the case thread fails.
pub fn run<F>(config: &Config, corpus: &[Vec<u8>], target: F) -> Result<Report, FuzzError>
where
    F: Fn(&[u8]) -> Outcome + Sync,
{
    let _ = (corpus, target);
    Ok(Report {
        target: config.target.clone(),
        ..Report::default()
    })
}

/// Runs `target` on each `*.bin` file of `dir` in name order.
///
/// A missing directory gives an empty report. The replay also runs a leftover `pending.bin`.
///
/// # Errors
///
/// Returns [`FuzzError`] when the directory or a file cannot be read.
pub fn replay_regress<F>(dir: &Path, target: F) -> Result<Report, FuzzError>
where
    F: Fn(&[u8]) -> Outcome + Sync,
{
    let _ = (dir, target);
    Ok(Report::default())
}

/// Installs a panic hook that counts each panic and then calls the previous hook.
///
/// A second call has no effect.
pub fn install_panic_counter() {}

/// Returns the number of panics since [`install_panic_counter`].
#[must_use]
pub fn panic_count() -> u64 {
    0
}
