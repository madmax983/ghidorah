//! The `xtask ci` command: the CI steps of both tiers and the time of each test.
//!
//! Output: `{ ok, steps: { <step>: { ok, seconds, .. } } }`.
//! AC-002 reads `/steps/offline_build/ok`. AC-021 reads `/steps/tier1/seconds`.
//! AC-224 reads `/steps/test_times/max_seconds`. AC-020 reads `/steps/test_hermetic/ok`.
//! AC-234 reads `/steps/fix_commits/ok`.

mod fixes;
mod hermetic;

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::json::Value;
use crate::{Error, proc};

pub use fixes::{
    FIX_PREFIX, LOG_FORMAT, fix_commit_count, fix_commits_without_tests, is_test_file,
};
pub use hermetic::{
    DATA_DIR, REMOVED_VARS, TestBinary, hermetic_env, run_binaries, run_hermetic, test_binaries,
};

/// The time cap of one tier-1 test in milliseconds (AC-224).
pub const TEST_CAP_MS: u64 = 15_000;

/// The time cap of the tier-1 run in seconds on the 4-core build host (AC-021).
pub const TIER1_CAP_SECS: u64 = 120;

/// The number of slow tests that the `test_times` step lists.
const SLOWEST: usize = 10;

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
    /// A tier-1 run with one test thread that records the time of each test.
    TestTimes,
    /// The tier-1 test binaries with `PATH` reduced to the toolchain and an empty `HOME`.
    TestHermetic,
    /// Each `fix:` commit changes at least one test file.
    FixCommits,
}

impl Step {
    /// Every step, in run order.
    pub const ALL: &[Self] = &[
        Self::Fmt,
        Self::Clippy,
        Self::Doc,
        Self::OfflineBuild,
        Self::Tier1,
        Self::Tier2,
        Self::TestTimes,
        Self::TestHermetic,
        Self::FixCommits,
    ];

    /// The steps of a run without `--steps` and without `--tier2`.
    pub const DEFAULT: &[Self] = &[
        Self::Fmt,
        Self::Clippy,
        Self::Doc,
        Self::OfflineBuild,
        Self::Tier1,
        Self::TestTimes,
        Self::TestHermetic,
        Self::FixCommits,
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
            Self::TestHermetic => "test_hermetic",
            Self::FixCommits => "fix_commits",
        }
    }

    /// Gives the step of a name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.name() == name)
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
    let usage = || Error::Usage("cargo xtask ci [--tier2] [--steps a,b,..]".to_owned());
    let mut tier2 = false;
    let mut picked: Option<Vec<Step>> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--tier2" => tier2 = true,
            "--steps" => {
                let list = rest.next().ok_or_else(usage)?;
                let steps = list
                    .split(',')
                    .map(|name| Step::parse(name.trim()).ok_or_else(usage))
                    .collect::<Result<Vec<_>, _>>()?;
                picked = Some(steps);
            }
            _ => return Err(usage()),
        }
    }
    let steps = picked.unwrap_or_else(|| {
        Step::ALL
            .iter()
            .copied()
            .filter(|s| Step::DEFAULT.contains(s) || (tier2 && *s == Step::Tier2))
            .collect()
    });
    let tier2 = tier2 || steps.contains(&Step::Tier2);
    Ok(Options { steps, tier2 })
}

/// The empty cargo home of the offline build step.
#[must_use]
pub fn offline_home(root: &Path) -> PathBuf {
    root.join("target").join("xtask-ci").join("cargo-home")
}

/// The separate target directory of the offline build step.
#[must_use]
pub fn offline_target(root: &Path) -> PathBuf {
    root.join("target").join("xtask-ci").join("offline-target")
}

/// Gives the command of a step.
///
/// Test steps set `GHIDORAH_REQUIRE_PROOFS=1`, so a stale proof fails the run (ADR-0011).
#[must_use]
pub fn command(root: &Path, step: Step) -> Command {
    let mut cmd = match step {
        Step::Fmt => proc::cargo_cmd(&["fmt", "--all", "--", "--check"]),
        Step::Clippy => proc::cargo_cmd(&[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ]),
        Step::Doc => {
            let mut cmd = proc::cargo_cmd(&["doc", "--workspace", "--no-deps"]);
            cmd.env("RUSTDOCFLAGS", "-Dwarnings");
            cmd
        }
        Step::OfflineBuild => {
            let mut cmd = proc::cargo_cmd(&[
                "build",
                "--workspace",
                "--all-targets",
                "--offline",
                "--locked",
            ]);
            cmd.env("CARGO_HOME", offline_home(root));
            cmd.env("CARGO_TARGET_DIR", offline_target(root));
            cmd
        }
        Step::Tier1 => proc::cargo_cmd(&["test", "--workspace", "--no-fail-fast"]),
        Step::Tier2 => proc::cargo_cmd(&[
            "test",
            "--workspace",
            "--no-fail-fast",
            "--",
            "--include-ignored",
        ]),
        Step::TestTimes => proc::cargo_cmd(&[
            "test",
            "--workspace",
            "--no-fail-fast",
            "--",
            "--test-threads=1",
        ]),
        Step::TestHermetic => hermetic::build_command(root),
        Step::FixCommits => fixes::log_command(root),
    };
    if matches!(step, Step::Tier1 | Step::Tier2 | Step::TestTimes) {
        cmd.env("GHIDORAH_REQUIRE_PROOFS", "1");
    }
    cmd.current_dir(root);
    cmd
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
    /// True when the test passes or libtest ignores it.
    pub ok: bool,
}

/// Gives the time of each test from timed libtest output lines.
///
/// Each line comes with its arrival time in milliseconds. The run uses one test thread,
/// so the time of a test is the gap since the line before it.
#[must_use]
pub fn parse_test_times(lines: &[(u64, String)]) -> Vec<TestTime> {
    let mut times = Vec::new();
    let mut binary: Option<usize> = None;
    let mut last = 0u64;
    for (at, line) in lines {
        if line.starts_with("running ") && (line.ends_with(" test") || line.ends_with(" tests")) {
            binary = Some(binary.map_or(0, |b| b + 1));
            last = *at;
            continue;
        }
        if line.starts_with("test result:") {
            continue;
        }
        let Some((name, result)) = line
            .strip_prefix("test ")
            .and_then(|r| r.split_once(" ... "))
        else {
            continue;
        };
        times.push(TestTime {
            binary: binary.unwrap_or(0),
            name: name.to_owned(),
            ms: at.saturating_sub(last),
            ok: result.starts_with("ok") || result.starts_with("ignored"),
        });
        last = *at;
    }
    times
}

/// Tells if a tier-1 run of `ms` milliseconds is within [`TIER1_CAP_SECS`].
#[must_use]
pub const fn tier1_within_cap(ms: u64) -> bool {
    ms <= TIER1_CAP_SECS.saturating_mul(1_000)
}

/// Gives the tests above [`TEST_CAP_MS`], slowest first.
#[must_use]
pub fn over_cap(times: &[TestTime]) -> Vec<&TestTime> {
    let mut out: Vec<&TestTime> = times.iter().filter(|t| t.ms > TEST_CAP_MS).collect();
    out.sort_by(|a, b| b.ms.cmp(&a.ms).then_with(|| a.name.cmp(&b.name)));
    out
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn step_report(ok: bool, ms: u64, extra: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let mut members: BTreeMap<String, Value> =
        extra.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    members.insert("ok".to_owned(), Value::from(ok));
    members.insert("seconds".to_owned(), Value::from(ms.div_ceil(1000)));
    Value::Object(members)
}

fn run_plain(root: &Path, step: Step) -> Result<Value, Error> {
    if step == Step::OfflineBuild {
        let home = offline_home(root);
        if home.exists() {
            std::fs::remove_dir_all(&home).map_err(|e| Error::io(&home, e))?;
        }
        std::fs::create_dir_all(&home).map_err(|e| Error::io(&home, e))?;
    }
    let start = Instant::now();
    let out = proc::run(&mut command(root, step))?;
    let ms = elapsed_ms(start);
    let mut extra = vec![(
        "code",
        out.code
            .map_or(Value::Null, |c| Value::Number(c.to_string())),
    )];
    if step == Step::Tier1 {
        extra.push(("cap_seconds", Value::from(TIER1_CAP_SECS)));
        extra.push(("within_cap", Value::from(tier1_within_cap(ms))));
    }
    if !out.ok() {
        let tail = format!(
            "{}\n{}",
            proc::tail(&out.stdout, 20),
            proc::tail(&out.stderr, 20)
        );
        extra.push(("tail", Value::from(tail)));
    }
    Ok(step_report(out.ok(), ms, extra))
}

/// Runs the `test_hermetic` step (AC-020).
fn run_hermetic_step(root: &Path) -> Result<Value, Error> {
    let start = Instant::now();
    let run = run_hermetic(root)?;
    let failed: Vec<Value> = run
        .failed
        .iter()
        .map(|(name, tail)| {
            Value::object([
                ("binary", Value::from(name.as_str())),
                ("tail", Value::from(tail.as_str())),
            ])
        })
        .collect();
    Ok(step_report(
        run.failed.is_empty() && run.binaries > 0,
        elapsed_ms(start),
        [
            ("binaries", Value::from(run.binaries)),
            (
                "toolchain",
                Value::from(run.toolchain.display().to_string()),
            ),
            ("failed", Value::from(failed)),
        ],
    ))
}

/// Runs the `fix_commits` step (AC-234).
fn run_fix_step(root: &Path) -> Result<Value, Error> {
    let start = Instant::now();
    let log = proc::run_ok(&mut fixes::log_command(root))?;
    let missing: Vec<Value> = fix_commits_without_tests(&log.stdout)
        .into_iter()
        .map(Value::from)
        .collect();
    Ok(step_report(
        missing.is_empty(),
        elapsed_ms(start),
        [
            ("commits", Value::from(fix_commit_count(&log.stdout))),
            ("missing", Value::from(missing)),
        ],
    ))
}

fn run_times(root: &Path) -> Result<Value, Error> {
    let mut cmd = command(root, Step::TestTimes);
    let argv = proc::describe(&cmd);
    let start = Instant::now();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| proc::start_error(&argv, &e))?;
    let mut lines = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).lines() {
            let line = line.map_err(|e| proc::start_error(&argv, &e))?;
            lines.push((elapsed_ms(start), line));
        }
    }
    let status = child.wait().map_err(|e| proc::start_error(&argv, &e))?;
    let mut times = parse_test_times(&lines);
    let max_ms = times.iter().map(|t| t.ms).max().unwrap_or(0);
    let failed: Vec<Value> = times
        .iter()
        .filter(|t| !t.ok)
        .map(|t| Value::from(t.name.as_str()))
        .collect();
    times.sort_by(|a, b| b.ms.cmp(&a.ms).then_with(|| a.name.cmp(&b.name)));
    let slowest: Vec<Value> = times
        .iter()
        .take(SLOWEST)
        .map(|t| {
            Value::object([
                ("name", Value::from(t.name.as_str())),
                ("ms", Value::from(t.ms)),
            ])
        })
        .collect();
    let within_cap = max_ms <= TEST_CAP_MS;
    let ok = status.success() && failed.is_empty() && within_cap;
    Ok(step_report(
        ok,
        elapsed_ms(start),
        [
            ("count", Value::from(times.len())),
            ("max_ms", Value::from(max_ms)),
            ("max_seconds", Value::from(max_ms.div_ceil(1000))),
            ("slowest", Value::from(slowest)),
            ("failed", Value::from(failed)),
        ],
    ))
}

/// Runs `xtask ci`.
///
/// # Errors
///
/// Returns an error for a bad command line or a process that does not start.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let options = parse_args(args)?;
    let mut ok = true;
    let mut steps = BTreeMap::new();
    for &step in &options.steps {
        let report = match step {
            Step::TestTimes => run_times(root)?,
            Step::TestHermetic => run_hermetic_step(root)?,
            Step::FixCommits => run_fix_step(root)?,
            _ => run_plain(root, step)?,
        };
        ok &= report.get("ok").and_then(Value::as_bool) == Some(true);
        steps.insert(step.name().to_owned(), report);
    }
    Ok(Value::object([
        ("ok", Value::from(ok)),
        ("steps", Value::Object(steps)),
    ]))
}
