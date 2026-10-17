//! The `xtask cov` command: line coverage with rustup `llvm-tools` (ADR-0027).
//!
//! Output: `{ ok, workspace: {..}, crates: { <dir>: {..} }, objects, tests_ok }`.
//! Percent values are integers in hundredths (`percent_x100`), so the output has no floats.
//!
//! Method: build and run the tier-1 tests with `-C instrument-coverage` in `target/cov`,
//! merge the profiles with `llvm-profdata`, then read `llvm-cov export --summary-only`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::json::{self, Value};
use crate::{Error, proc, workspace};

/// The minimum line coverage of the workspace in percent (AC-013).
pub const WORKSPACE_MIN: u64 = 85;

/// The minimum line coverage of each core crate in percent (AC-013).
pub const CORE_MIN: u64 = 90;

/// The minimum line coverage of `ghidorah-kernel` in percent (AC-013).
pub const KERNEL_MIN: u64 = 95;

/// The core crates of AC-013, as directory names under `crates/`.
pub const CORE: &[&str] = &[
    "json", "loader", "x86", "ir", "db", "analysis", "decomp", "tools",
];

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

impl Counts {
    fn add(&mut self, other: Self) {
        self.lines = self.lines.saturating_add(other.lines);
        self.covered = self.covered.saturating_add(other.covered);
        self.regions = self.regions.saturating_add(other.regions);
        self.regions_covered = self.regions_covered.saturating_add(other.regions_covered);
    }
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
    if dir == "kernel" {
        Some(KERNEL_MIN)
    } else if CORE.contains(&dir) {
        Some(CORE_MIN)
    } else {
        None
    }
}

/// Gives the crate directory of a measured source file, or `None` when the file is out of scope.
///
/// Out of scope: files outside `crates/*/src`, `tests.rs` files, `tests/` directories and dev crates.
#[must_use]
pub fn crate_of(rel: &str) -> Option<&str> {
    let mut parts = rel.split('/');
    let (Some("crates"), Some(dir), Some("src")) = (parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let rest: Vec<&str> = parts.collect();
    let test_file = rest.last() == Some(&"tests.rs") || rest.contains(&"tests");
    (!test_file && !rest.is_empty() && !DEV_DIRS.contains(&dir)).then_some(dir)
}

fn count(summary: &Value, kind: &str, key: &str) -> u64 {
    summary
        .get(kind)
        .and_then(|k| k.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// Sums the per-file totals of `llvm-cov export --summary-only` by crate.
///
/// # Errors
///
/// Returns [`Error::Data`] when the export has a bad form.
pub fn summarize(root: &Path, export: &Value) -> Result<Coverage, Error> {
    let bad = |what: &str| Error::data("llvm-cov export", what);
    let files = export
        .pointer("/data/0/files")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("no `/data/0/files` array"))?;
    let mut coverage = Coverage::default();
    for file in files {
        let name = file
            .get("filename")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("a file has no name"))?;
        let path = Path::new(name);
        if !path.starts_with(root) {
            continue;
        }
        let rel = workspace::rel(root, path);
        let Some(dir) = crate_of(&rel) else {
            continue;
        };
        let summary = file
            .get("summary")
            .ok_or_else(|| bad("a file has no summary"))?;
        let counts = Counts {
            lines: count(summary, "lines", "count"),
            covered: count(summary, "lines", "covered"),
            regions: count(summary, "regions", "count"),
            regions_covered: count(summary, "regions", "covered"),
        };
        coverage
            .crates
            .entry(dir.to_owned())
            .or_default()
            .add(counts);
    }
    Ok(coverage)
}

fn percent_x100(covered: u64, total: u64) -> u64 {
    if total == 0 {
        10_000
    } else {
        u64::try_from(u128::from(covered) * 10_000 / u128::from(total)).unwrap_or(10_000)
    }
}

fn meets(counts: Counts, min: u64) -> bool {
    u128::from(counts.covered) * 100 >= u128::from(min) * u128::from(counts.lines)
}

fn report(counts: Counts, min: Option<u64>) -> (bool, Value) {
    let ok = min.is_none_or(|m| meets(counts, m));
    let value = Value::object([
        ("lines", Value::from(counts.lines)),
        ("covered", Value::from(counts.covered)),
        (
            "percent_x100",
            Value::from(percent_x100(counts.covered, counts.lines)),
        ),
        ("regions", Value::from(counts.regions)),
        ("regions_covered", Value::from(counts.regions_covered)),
        ("min_percent", min.map_or(Value::Null, Value::from)),
        ("ok", Value::from(ok)),
    ]);
    (ok, value)
}

/// Applies the thresholds and gives the JSON report with its `ok` member.
///
/// A crate with zero instrumented lines has no gate yet.
#[must_use]
pub fn gate(coverage: &Coverage) -> Value {
    let mut all = Counts::default();
    let mut ok = true;
    let mut crates = BTreeMap::new();
    for (dir, counts) in &coverage.crates {
        all.add(*counts);
        let min = min_percent(dir).filter(|_| counts.lines > 0);
        let (crate_ok, value) = report(*counts, min);
        ok &= crate_ok;
        crates.insert(dir.clone(), value);
    }
    let (workspace_ok, workspace) = report(all, (all.lines > 0).then_some(WORKSPACE_MIN));
    Value::object([
        ("ok", Value::from(ok && workspace_ok)),
        ("workspace", workspace),
        ("crates", Value::Object(crates)),
    ])
}

/// Gives the executables of `cargo test --no-run --message-format=json` output.
#[must_use]
pub fn test_objects(cargo_json: &str) -> Vec<PathBuf> {
    cargo_json
        .lines()
        .filter_map(|line| json::parse(line).ok())
        .filter(|msg| msg.get("reason").and_then(Value::as_str) == Some("compiler-artifact"))
        .filter_map(|msg| {
            msg.get("executable")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
        .collect()
}

/// The paths of the llvm tools of the active toolchain.
struct Tools {
    profdata: PathBuf,
    cov: PathBuf,
}

fn llvm_tools() -> Result<Tools, Error> {
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let sysroot = proc::run_ok(Command::new(&rustc).args(["--print", "sysroot"]))?;
    let version = proc::run_ok(Command::new(&rustc).arg("-vV"))?;
    let host = version
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or_else(|| Error::data("rustc -vV", "no host line"))?;
    let bin = PathBuf::from(sysroot.stdout.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin");
    let tools = Tools {
        profdata: bin.join("llvm-profdata"),
        cov: bin.join("llvm-cov"),
    };
    if tools.profdata.is_file() && tools.cov.is_file() {
        Ok(tools)
    } else {
        Err(Error::data(
            bin.display().to_string(),
            "llvm-profdata or llvm-cov is missing; run `rustup component add llvm-tools`",
        ))
    }
}

fn instrumented(root: &Path, target: &Path, profiles: &Path, args: &[&str]) -> Command {
    let mut cmd = proc::cargo_cmd(args);
    cmd.current_dir(root)
        .env("RUSTFLAGS", "-C instrument-coverage")
        .env("CARGO_TARGET_DIR", target)
        .env("LLVM_PROFILE_FILE", profiles.join("%p-%m.profraw"));
    cmd
}

fn profraw_files(dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| Error::io(dir, e))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "profraw"))
        .collect();
    files.sort();
    Ok(files)
}

/// Runs `xtask cov`.
///
/// # Errors
///
/// Returns an error when a build, a tool or a file operation fails.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    if !args.is_empty() {
        return Err(Error::Usage("cargo xtask cov".to_owned()));
    }
    let tools = llvm_tools()?;
    let target = root.join("target").join("cov");
    let profiles = target.join("profraw");
    if profiles.exists() {
        std::fs::remove_dir_all(&profiles).map_err(|e| Error::io(&profiles, e))?;
    }
    std::fs::create_dir_all(&profiles).map_err(|e| Error::io(&profiles, e))?;
    let build = ["test", "--workspace", "--no-run", "--message-format=json"];
    let listing = proc::run_ok(&mut instrumented(root, &target, &profiles, &build))?;
    let objects = test_objects(&listing.stdout);
    let tests = proc::run(&mut instrumented(
        root,
        &target,
        &profiles,
        &["test", "--workspace"],
    ))?;
    let raw = profraw_files(&profiles)?;
    let coverage = if raw.is_empty() || objects.is_empty() {
        Coverage::default()
    } else {
        let merged = target.join("merged.profdata");
        let mut merge = Command::new(&tools.profdata);
        merge
            .args(["merge", "-sparse", "-o"])
            .arg(&merged)
            .args(&raw);
        proc::run_ok(&mut merge)?;
        let mut export = Command::new(&tools.cov);
        export
            .args(["export", "--summary-only", "--instr-profile"])
            .arg(&merged);
        for (i, object) in objects.iter().enumerate() {
            if i > 0 {
                export.arg("--object");
            }
            export.arg(object);
        }
        let out = proc::run_ok(&mut export)?;
        let value =
            json::parse(&out.stdout).map_err(|e| Error::data("llvm-cov export", e.to_string()))?;
        summarize(root, &value)?
    };
    let mut report = gate(&coverage);
    if let Value::Object(members) = &mut report {
        let ok = members.get("ok").and_then(Value::as_bool) == Some(true) && tests.ok();
        members.insert("ok".to_owned(), Value::from(ok));
        members.insert("tests_ok".to_owned(), Value::from(tests.ok()));
        members.insert("objects".to_owned(), Value::from(objects.len()));
    }
    Ok(report)
}
