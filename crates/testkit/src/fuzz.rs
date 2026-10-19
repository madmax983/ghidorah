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
//!
//! `xtask fuzz` runs long batches of a target binary with [`SEED_ENV`]. Then each batch
//! uses a new seed, and the run saves the shrunk input of each failed case.

mod havoc;

use std::cell::Cell;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::pbt::panic_text;
use crate::rng::{Xoshiro256ss, below, fnv1a64};

/// The number of case panics that the hook prints with the previous hook.
const PRINTED_PANICS: u64 = 8;

thread_local! {
    /// `true` while this thread runs a fuzz case.
    static IN_CASE: Cell<bool> = const { Cell::new(false) };
}

/// The panic count since [`install_panic_counter`].
static PANICS: AtomicU64 = AtomicU64::new(0);

/// Guards the one-time hook install.
static HOOK: Once = Once::new();

/// The file name of the input of the running case.
pub const PENDING_FILE: &str = "pending.bin";

/// The default stack size of the case thread (256 KiB).
pub const DEFAULT_STACK: usize = 256 * 1024;

/// The default largest input length.
pub const DEFAULT_MAX_LEN: usize = 4096;

/// The variable that gives the batch seed of a long run (`xtask fuzz`, design Section 13.5).
///
/// Without it, a run uses the fixed seed of its [`Config`]. With it, the run mixes the batch
/// seed into that seed. Then it shrinks each failed case and saves its input in the pending
/// directory as `crash-<case>.input`.
pub const SEED_ENV: &str = "FUZZ_SEED";

/// The file extension of a failing input that a long run saves.
pub const CRASH_EXT: &str = "input";

/// The largest number of target runs of one shrink in a long run.
pub const SHRINK_BUDGET: u32 = 2_000;

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
            seed: fnv1a64(target.as_bytes()),
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
        self.panics == 0 && self.violations == 0
    }

    /// Returns the share of cases that reached `stage`, in percent (0 to 100).
    #[must_use]
    pub fn reached_percent(&self, stage: usize) -> u64 {
        if self.cases == 0 {
            return 0;
        }
        let reached = self.reached.get(stage).copied().unwrap_or(0);
        reached.saturating_mul(100) / u64::from(self.cases)
    }

    /// Counts a case whose deepest stage is `stage`.
    fn count_stage(&mut self, stage: usize) {
        if self.reached.len() <= stage {
            self.reached.resize(stage + 1, 0);
        }
        for slot in self.reached.iter_mut().take(stage + 1) {
            *slot += 1;
        }
    }

    /// Keeps a failed case while the report has room.
    fn keep(&mut self, max: usize, case: u32, input: &[u8], message: String) {
        if self.crashes.len() < max {
            self.crashes.push(Crash {
                case,
                input: input.to_vec(),
                message,
            });
        }
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
    havoc::mutate(rng, input, max_len)
}

/// The `SplitMix64` output function: it spreads the bits of one batch number.
const fn splitmix(value: u64) -> u64 {
    let mut z = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Gives the seed of a run: `seed` alone, or `seed` mixed with the batch seed of a long run.
#[must_use]
pub const fn batch_seed(seed: u64, batch: Option<u64>) -> u64 {
    match batch {
        None => seed,
        Some(b) => seed ^ splitmix(b.wrapping_add(1)),
    }
}

/// Reads the batch seed of [`SEED_ENV`]: a decimal or `0x` hex number.
fn env_batch() -> Option<u64> {
    let text = std::env::var(SEED_ENV).ok()?;
    let text = text.trim();
    text.strip_prefix("0x").map_or_else(
        || text.parse().ok(),
        |hex| u64::from_str_radix(hex, 16).ok(),
    )
}

/// Gives the file name of the saved input of the failed case `case`: `crash-<case>.input`.
#[must_use]
pub fn crash_name(case: u32) -> String {
    format!("crash-{case}.{CRASH_EXT}")
}

/// Tells if one run of `target` on `input` panics or gives a violation.
fn case_fails<F>(target: &F, input: &[u8]) -> bool
where
    F: Fn(&[u8]) -> Outcome,
{
    IN_CASE.with(|c| c.set(true));
    let result = catch_unwind(AssertUnwindSafe(|| target(input)));
    IN_CASE.with(|c| c.set(false));
    result.map_or(true, |outcome| outcome.violation.is_some())
}

/// Shrinks the failing input `input` of `target` with at most `budget` target runs.
///
/// A case fails when the target panics or gives a violation. The result fails too. An input
/// that does not fail comes back unchanged.
pub fn shrink_input<F>(input: &[u8], target: &F, budget: u32) -> Vec<u8>
where
    F: Fn(&[u8]) -> Outcome,
{
    if !case_fails(target, input) {
        return input.to_vec();
    }
    let to_bytes = |c: &[u64]| -> Vec<u8> {
        c.iter()
            .map(|&v| u8::try_from(v).unwrap_or(u8::MAX))
            .collect()
    };
    let wide: Vec<u64> = input.iter().map(|&b| u64::from(b)).collect();
    let shrunk =
        crate::pbt::shrink_with_budget(&wide, budget, |c| case_fails(target, &to_bytes(c)));
    to_bytes(&shrunk)
}

/// Saves the shrunk input of each failed case of `report` in `dir` (a long run).
fn save_crashes<F>(dir: &Path, report: &Report, target: &F) -> Result<(), FuzzError>
where
    F: Fn(&[u8]) -> Outcome,
{
    for crash in &report.crashes {
        let small = shrink_input(&crash.input, target, SHRINK_BUDGET);
        let path = dir.join(crash_name(crash.case));
        std::fs::write(&path, small).map_err(|e| io_error(&path, &e))?;
    }
    Ok(())
}

fn io_error(path: &Path, e: &std::io::Error) -> FuzzError {
    FuzzError::Io {
        path: path.display().to_string(),
        message: e.to_string(),
    }
}

/// Runs one case and adds its result to `report`.
fn run_case<F>(
    pending: Option<&Path>,
    case: u32,
    input: &[u8],
    target: &F,
    report: &mut Report,
    max_crashes: usize,
) -> Result<(), FuzzError>
where
    F: Fn(&[u8]) -> Outcome,
{
    if let Some(path) = pending {
        std::fs::write(path, input).map_err(|e| io_error(path, &e))?;
    }
    IN_CASE.with(|c| c.set(true));
    let result = catch_unwind(AssertUnwindSafe(|| target(input)));
    IN_CASE.with(|c| c.set(false));
    report.cases += 1;
    match result {
        Ok(outcome) => {
            report.count_stage(outcome.stage);
            if let Some(message) = outcome.violation {
                report.violations += 1;
                report.keep(max_crashes, case, input, message);
            }
        }
        Err(payload) => {
            report.panics += 1;
            let message = format!("panic: {}", panic_text(payload.as_ref()));
            report.keep(max_crashes, case, input, message);
        }
    }
    if let Some(path) = pending {
        std::fs::remove_file(path).map_err(|e| io_error(path, &e))?;
    }
    Ok(())
}

/// Runs `body` in a named thread with `stack_size` bytes of stack.
fn in_thread<T, B>(name: &str, stack_size: usize, body: B) -> Result<T, FuzzError>
where
    T: Send,
    B: FnOnce() -> Result<T, FuzzError> + Send,
{
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .name(format!("fuzz-{name}"))
            .stack_size(stack_size)
            .spawn_scoped(scope, body)
            .map_err(|e| FuzzError::Thread(e.to_string()))?;
        handle
            .join()
            .map_err(|_| FuzzError::Thread("the case thread stopped with a panic".to_string()))?
    })
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
    install_panic_counter();
    let batch = env_batch();
    let pending = match &config.pending_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(|e| io_error(dir, &e))?;
            Some(dir.join(PENDING_FILE))
        }
        None => None,
    };
    in_thread(&config.target, config.stack_size, || {
        let mut rng = Xoshiro256ss::seed_from_u64(batch_seed(config.seed, batch));
        let mut report = Report {
            target: config.target.clone(),
            reached: vec![0; config.stages.len()],
            ..Report::default()
        };
        let count = u64::try_from(corpus.len()).unwrap_or(u64::MAX);
        for case in 0..config.cases {
            let seed: &[u8] = if count == 0 {
                &[]
            } else {
                let i = usize::try_from(below(&mut rng, count)).unwrap_or(0);
                corpus.get(i).map_or(&[], Vec::as_slice)
            };
            let input = mutate(&mut rng, seed, config.max_len);
            run_case(
                pending.as_deref(),
                case,
                &input,
                &target,
                &mut report,
                config.max_crashes,
            )?;
        }
        if let (Some(_), Some(dir)) = (batch, config.pending_dir.as_deref()) {
            save_crashes(dir, &report, &target)?;
        }
        Ok(report)
    })
}

/// Returns the sorted `*.bin` files of `dir`. A missing directory gives no files.
fn regress_files(dir: &Path) -> Result<Vec<PathBuf>, FuzzError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_error(dir, &e)),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| io_error(dir, &e))?.path();
        if path.is_file() && path.extension().is_some_and(|x| x == "bin") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Runs `target` on each `*.bin` file of `dir` in name order.
///
/// A missing directory gives an empty report. The replay also runs a leftover `pending.bin`.
///
/// # Errors
///
/// Returns [`FuzzError`] when the function cannot read the directory or a file.
pub fn replay_regress<F>(dir: &Path, target: F) -> Result<Report, FuzzError>
where
    F: Fn(&[u8]) -> Outcome + Sync,
{
    install_panic_counter();
    let files = regress_files(dir)?;
    let name = dir.display().to_string();
    in_thread("replay", DEFAULT_STACK, || {
        let mut report = Report {
            target: name.clone(),
            ..Report::default()
        };
        for (i, path) in files.iter().enumerate() {
            let input = std::fs::read(path).map_err(|e| io_error(path, &e))?;
            let case = u32::try_from(i).unwrap_or(u32::MAX);
            run_case(None, case, &input, &target, &mut report, usize::MAX)?;
        }
        Ok(report)
    })
}

/// Installs a panic hook that counts each panic and then calls the previous hook.
///
/// The hook prints each panic through the previous hook, except panics in fuzz
/// cases after the first 8. So a long fuzz run stays quiet, and a test failure
/// still shows its message. A second call has no effect.
pub fn install_panic_counter() {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let seen = PANICS.fetch_add(1, Ordering::SeqCst);
            let quiet = IN_CASE.with(Cell::get) && seen >= PRINTED_PANICS;
            if !quiet {
                previous(info);
            }
        }));
    });
}

/// Returns the number of panics since [`install_panic_counter`].
#[must_use]
pub fn panic_count() -> u64 {
    PANICS.load(Ordering::SeqCst)
}
