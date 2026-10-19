//! The `xtask fuzz` command: long runs of every fuzz target of design Section 13.5 (AC-190b).
//!
//! Each target is one test binary `crates/<crate>/tests/fuzz_<target>.rs` with one test
//! function. One batch is one run of that binary in a child process with the variable
//! `FUZZ_SEED`. The harness of `testkit::fuzz` mixes the batch seed into its fixed seed, so
//! each batch runs new cases. A wall-clock watchdog stops a batch that hangs.
//!
//! After each batch, the command moves each failing input to
//! `tests/regress/<target>/<sha8>.bin`. The harness shrinks a panic or a violation before it
//! saves the input. A `pending.bin` from an abort, a stack overflow or a hang keeps its bytes.
//! Every later test run replays the regression files.
//!
//! A batch with a saved input, a hang or a signal is a violation. A batch that fails with an
//! exit code and saves no input is a stage miss: an assertion of the test outside the cases
//! fails. An example is a stage share of design Section 13.5 with a new batch seed. The tier-1
//! run with the fixed seed is the gate of these assertions.
//!
//! Output: `{ ok, iters, seed, violations, targets: { <target>: { batches, cases, failed,
//! hangs, stage_misses, saved } } }`. AC-190b reads `/violations`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::json::Value;
use crate::verify::tree::sha256;
use crate::{Error, Finding, ci, proc};

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

/// Makes a table row.
const fn target(name: &'static str, dir: &'static str, package: &'static str) -> Target {
    Target {
        name,
        dir,
        package,
        cases: 2_000,
    }
}

/// The fuzz targets of design Section 13.5.
pub const TARGETS: &[Target] = &[
    target("elf_load", "crates/loader", "ghidorah-loader"),
    target("x86_decode", "crates/x86", "ghidorah-x86"),
    target("eh_frame", "crates/loader", "ghidorah-loader"),
    target("cparse", "crates/types", "ghidorah-types"),
    target("json_parse", "crates/json", "ghidorah-json"),
    target("addr_expr", "crates/base", "ghidorah-base"),
    target("calc", "crates/tools", "ghidorah-tools"),
    target("cursor_decode", "crates/tools", "ghidorah-tools"),
    target("mcp_line", "crates/cli", "ghidorah"),
    target("batch_parse", "crates/tools", "ghidorah-tools"),
    Target {
        cases: 10_000,
        ..target("pe_load", "crates/loader", "ghidorah-loader")
    },
    target("x86_lift_interp", "crates/x86", "ghidorah-x86"),
    target("journal_replay", "crates/db", "ghidorah-db"),
    target("snapshot_load", "crates/db", "ghidorah-db"),
    target("project_json", "crates/db", "ghidorah-db"),
    target("pipeline_raw", "crates/tools", "ghidorah-tools"),
    target("pipeline_elf", "crates/tools", "ghidorah-tools"),
];

/// The default number of cases of each target (design Section 13.5).
pub const DEFAULT_ITERS: u64 = 100_000;

/// The default watchdog limit of one batch in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 900;

/// The largest number of failed batches of one target. Later batches do not run.
pub const MAX_FAILED_BATCHES: u64 = 3;

/// The poll interval of the watchdog.
const POLL: Duration = Duration::from_millis(50);

/// The usage text.
const USAGE: &str = "cargo xtask fuzz [<target>..] [--iters N] [--seed S] [--timeout SECS]";

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
    let usage = || Error::Usage(USAGE.to_owned());
    let mut options = Options {
        targets: Vec::new(),
        iters: DEFAULT_ITERS,
        seed: 0,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    };
    let mut names = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut number = || -> Result<u64, Error> {
            rest.next()
                .and_then(|n| n.parse::<u64>().ok())
                .ok_or_else(usage)
        };
        match arg.as_str() {
            "--iters" => options.iters = number()?,
            "--seed" => options.seed = number()?,
            "--timeout" => options.timeout_secs = number()?,
            name if !name.starts_with('-') && TARGETS.iter().any(|t| t.name == name) => {
                names.push(name.to_owned());
            }
            _ => return Err(usage()),
        }
    }
    options.targets = TARGETS
        .iter()
        .filter(|t| names.is_empty() || names.iter().any(|n| n == t.name))
        .collect();
    Ok(options)
}

/// Gives the number of batches of `iters` cases for a target with `cases` cases per batch.
#[must_use]
pub const fn batches(iters: u64, cases: u32) -> u64 {
    if cases == 0 {
        return 0;
    }
    iters.div_ceil(cases as u64)
}

/// Gives the `FUZZ_SEED` value of batch `batch` of a run with the seed `seed`.
#[must_use]
pub const fn batch_seed(seed: u64, batch: u64) -> u64 {
    seed.wrapping_add(batch)
}

/// Gives the regression file name of an input: the first 8 hex digits of its SHA-256 and
/// `.bin`.
#[must_use]
pub fn regress_name(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(12);
    for b in sha256(bytes).iter().take(4) {
        let _ = write!(out, "{b:02x}");
    }
    out.push_str(".bin");
    out
}

/// Gives the test file of `target`, relative to the workspace root.
#[must_use]
pub fn test_file(target: &Target) -> String {
    format!("{}/tests/fuzz_{}.rs", target.dir, target.name)
}

/// Gives the case count of the configuration `::new("<target>", N)` in `text`, or `None`.
fn configured_cases(target: &Target, text: &str) -> Option<u64> {
    let key = format!("::new(\"{}\", ", target.name);
    let at = text.find(&key)?;
    let digits: String = text
        .get(at + key.len()..)?
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .filter(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// Gives the name of the first `#[test]` function of `text`, or `None`.
#[must_use]
pub fn test_name(text: &str) -> Option<String> {
    let after = text.split_once("#[test]")?.1;
    let name = after.split_once("fn ")?.1;
    let end = name.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))?;
    name.get(..end).map(str::to_owned)
}

/// Tells if `name` is a test name of `target`: `fuzz_<target>`, or an AC name that ends with
/// `_fuzz_<target>`.
fn is_target_test(target: &Target, name: &str) -> bool {
    let plain = format!("fuzz_{}", target.name);
    name == plain || (name.starts_with("ac_") && name.ends_with(&format!("_{plain}")))
}

/// Checks the source text of the test file of `target`. Gives one message per problem.
///
/// The file has one `#[test]` function `fuzz_<target>` or `ac_<nnn>_fuzz_<target>`. It replays
/// the regression files of `tests/regress/<target>`, and its configuration has at least the
/// cases of the table.
#[must_use]
pub fn source_problems(target: &Target, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let tests = text.matches("#[test]").count();
    if tests != 1 {
        out.push(format!("the file has {tests} test functions, not 1"));
    }
    if !test_name(text).is_some_and(|n| is_target_test(target, &n)) {
        out.push(format!("no test function fuzz_{}", target.name));
    }
    if !text.contains("replay_regress") {
        out.push("no replay of the regression files".to_owned());
    }
    if !text.contains(&format!("tests/regress/{}", target.name)) {
        out.push(format!(
            "no regression directory tests/regress/{}",
            target.name
        ));
    }
    match configured_cases(target, text) {
        Some(n) if n >= u64::from(target.cases) => {}
        Some(n) => out.push(format!("{n} cases, below {}", target.cases)),
        None => out.push(format!("no configuration ::new(\"{}\", N)", target.name)),
    }
    out
}

/// AC-190a: checks the test file of every target. Gives one finding per problem.
#[must_use]
pub fn check_targets(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for t in TARGETS {
        let file = test_file(t);
        match std::fs::read_to_string(root.join(&file)) {
            Ok(text) => out.extend(
                source_problems(t, &text)
                    .into_iter()
                    .map(|p| Finding::new("AC-190a", file.as_str(), 0, p)),
            ),
            Err(e) => out.push(Finding::new("AC-190a", file.as_str(), 0, e.to_string())),
        }
    }
    out
}

/// Gives the regression directory of `target`.
#[must_use]
pub fn regress_dir(root: &Path, target: &Target) -> PathBuf {
    root.join("tests/regress").join(target.name)
}

/// Tells if `name` is a failing input of a batch: `crash-<case>.input` or `pending.bin`.
fn is_failing_input(name: &str) -> bool {
    name == "pending.bin"
        || (name.starts_with("crash-") && Path::new(name).extension().is_some_and(|x| x == "input"))
}

/// Moves the failing inputs of a batch in `dir` to `<sha8>.bin` files. Gives the new names.
///
/// The inputs are the `crash-<case>.input` files of the harness and a left `pending.bin`.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file does not read, write or move.
pub fn collect(dir: &Path) -> Result<Vec<String>, Error> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(dir, e)),
    };
    let mut inputs: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| Error::io(dir, e))?.path();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        if name.is_some_and(|n| is_failing_input(&n)) {
            inputs.push(path);
        }
    }
    inputs.sort();
    let mut saved = Vec::new();
    for path in inputs {
        let bytes = std::fs::read(&path).map_err(|e| Error::io(&path, e))?;
        let name = regress_name(&bytes);
        let target = dir.join(&name);
        std::fs::write(&target, &bytes).map_err(|e| Error::io(&target, e))?;
        std::fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
        saved.push(name);
    }
    saved.sort();
    saved.dedup();
    Ok(saved)
}

/// The end of one batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// The test passed.
    Pass,
    /// The test failed.
    Fail {
        /// `true` when a signal stopped the process, for example on an abort.
        signal: bool,
    },
    /// The watchdog stopped the process.
    Hang,
}

/// The verdict of one batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The batch passed and saved no input.
    Pass,
    /// A case failed, the process stopped on a signal or the watchdog stopped it.
    Violation,
    /// The test failed with an exit code and saved no input.
    StageMiss,
}

/// Gives the verdict of a batch with the end `end`. `saved` is `true` when the batch saved a
/// failing input.
#[must_use]
pub const fn classify(end: End, saved: bool) -> Verdict {
    match (end, saved) {
        (_, true) | (End::Hang | End::Fail { signal: true }, false) => Verdict::Violation,
        (End::Fail { signal: false }, false) => Verdict::StageMiss,
        (End::Pass, false) => Verdict::Pass,
    }
}

/// Builds the test binary of `target` and gives its executable and package directory.
fn build(root: &Path, target: &Target) -> Result<ci::TestBinary, Error> {
    let test = format!("fuzz_{}", target.name);
    let mut cmd = proc::cargo_cmd(&[
        "test",
        "-p",
        target.package,
        "--test",
        &test,
        "--no-run",
        "--message-format=json",
    ]);
    let out = proc::run_ok(cmd.current_dir(root))?;
    let prefix = format!("{test}-");
    ci::test_binaries(&out.stdout)
        .into_iter()
        .find(|b| {
            b.exe
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(&prefix))
        })
        .ok_or_else(|| Error::data(format!("cargo test --test {test}"), "no test binary"))
}

/// Runs one batch of the test `test` of `binary` with the batch seed `seed` and the watchdog
/// `timeout`.
fn run_batch(
    binary: &ci::TestBinary,
    test: &str,
    seed: u64,
    timeout: Duration,
) -> Result<End, Error> {
    let mut cmd = Command::new(&binary.exe);
    cmd.args(["--exact", test, "--test-threads=1", "-q"])
        .current_dir(&binary.dir)
        .env("CARGO_MANIFEST_DIR", &binary.dir)
        .env("FUZZ_SEED", seed.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let argv = proc::describe(&cmd);
    let mut child = cmd.spawn().map_err(|e| proc::start_error(&argv, &e))?;
    let start = Instant::now();
    // The watchdog bounds the wait: the loop ends at the exit or at the time limit.
    loop {
        if let Some(status) = child.try_wait().map_err(|e| proc::start_error(&argv, &e))? {
            return Ok(if status.success() {
                End::Pass
            } else {
                End::Fail {
                    signal: status.code().is_none(),
                }
            });
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(End::Hang);
        }
        std::thread::sleep(POLL);
    }
}

/// The result of the batches of one target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Summary {
    batches: u64,
    failed: u64,
    hangs: u64,
    stage_misses: u64,
    saved: Vec<String>,
}

/// Runs the batches of one target.
fn run_target(root: &Path, target: &Target, options: &Options) -> Result<Summary, Error> {
    let binary = build(root, target)?;
    let file = root.join(test_file(target));
    let source = std::fs::read_to_string(&file).map_err(|e| Error::io(&file, e))?;
    let test =
        test_name(&source).ok_or_else(|| Error::data(test_file(target), "no test function"))?;
    let dir = regress_dir(root, target);
    let timeout = Duration::from_secs(options.timeout_secs);
    let mut out = Summary::default();
    for batch in 0..batches(options.iters, target.cases) {
        let end = run_batch(&binary, &test, batch_seed(options.seed, batch), timeout)?;
        out.batches = out.batches.saturating_add(1);
        let saved = collect(&dir)?;
        if end == End::Hang {
            out.hangs = out.hangs.saturating_add(1);
        }
        match classify(end, !saved.is_empty()) {
            Verdict::Pass => {}
            Verdict::StageMiss => out.stage_misses = out.stage_misses.saturating_add(1),
            Verdict::Violation => out.failed = out.failed.saturating_add(1),
        }
        out.saved.extend(saved);
        if out.failed >= MAX_FAILED_BATCHES {
            break;
        }
    }
    Ok(out)
}

/// Runs `xtask fuzz`.
///
/// # Errors
///
/// Returns an error for a bad command line, a build that fails or a process that does not
/// start.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let options = parse_args(args)?;
    let mut violations = 0u64;
    let mut targets = BTreeMap::new();
    for target in &options.targets {
        let s = run_target(root, target, &options)?;
        violations = violations.saturating_add(s.failed);
        let saved: Vec<Value> = s.saved.iter().map(|n| Value::from(n.as_str())).collect();
        targets.insert(
            target.name.to_owned(),
            Value::object([
                ("batches", Value::from(s.batches)),
                (
                    "cases",
                    Value::from(s.batches.saturating_mul(u64::from(target.cases))),
                ),
                ("failed", Value::from(s.failed)),
                ("hangs", Value::from(s.hangs)),
                ("stage_misses", Value::from(s.stage_misses)),
                ("saved", Value::from(saved)),
            ]),
        );
    }
    Ok(Value::object([
        ("ok", Value::from(violations == 0)),
        ("iters", Value::from(options.iters)),
        ("seed", Value::from(options.seed)),
        ("violations", Value::from(violations)),
        ("targets", Value::Object(targets)),
    ]))
}
