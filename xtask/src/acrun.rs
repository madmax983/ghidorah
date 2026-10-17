//! The evidence runner of `xtask ac --run` and the table `docs/ac-evidence.json`.
//!
//! Tier-1 test items always run. Tier-2 test items, `cmd:` items and `xtask:` items run only
//! with `--tier2`. A `record:` item gives `recorded` when its file and pointer exist.
//! The hash check of the named input belongs to WP-28 (AC-018b).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use crate::ac::{AcRow, Evidence, Op, Tier, is_template};
use crate::json::{self, Value};
use crate::{Error, proc, workspace};

/// The evidence table, relative to the workspace root.
pub const TABLE_PATH: &str = "docs/ac-evidence.json";

/// The status of one evidence item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// The item ran and passed.
    Pass,
    /// The item ran and failed.
    Fail,
    /// The record exists, and its pointer resolves.
    Recorded,
    /// The item did not run in this tier.
    Skipped,
}

impl Status {
    /// Gives the status name of the table.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Recorded => "recorded",
            Self::Skipped => "skipped",
        }
    }
}

/// The result of one evidence item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The AC ID.
    pub ac: String,
    /// The tier of the item.
    pub tier: Tier,
    /// The kind name of the item.
    pub kind: &'static str,
    /// The status.
    pub status: Status,
}

/// Compares a JSON value with the expected JSON text of an `xtask:` item.
///
/// `==` and `!=` compare the values. The other operators compare numbers only.
#[must_use]
pub fn compare(actual: &Value, op: Op, expected: &str) -> bool {
    let wanted = json::parse(expected).unwrap_or_else(|_| Value::from(expected));
    let numbers = actual.as_f64().zip(wanted.as_f64());
    let equal = numbers.map_or_else(|| *actual == wanted, |(a, b)| a.total_cmp(&b).is_eq());
    match op {
        Op::Eq => equal,
        Op::Ne => !equal,
        _ => numbers.is_some_and(|(a, b)| match op {
            Op::Le => a <= b,
            Op::Ge => a >= b,
            Op::Lt => a < b,
            _ => a > b,
        }),
    }
}

/// Gives the status of each test name in libtest output.
///
/// A name matches a line `test <path> ... <result>` when `<path>` equals it or ends with `::<name>`.
#[must_use]
pub fn test_statuses(stdout: &str, names: &[&str]) -> Vec<Status> {
    let results: Vec<(&str, &str)> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("test ")?.split_once(" ... "))
        .collect();
    names
        .iter()
        .map(|name| {
            let suffix = format!("::{name}");
            results
                .iter()
                .find(|(path, _)| path == name || path.ends_with(&suffix))
                .map_or(Status::Fail, |(_, result)| {
                    if result.starts_with("ok") {
                        Status::Pass
                    } else if result.starts_with("ignored") {
                        Status::Skipped
                    } else {
                        Status::Fail
                    }
                })
        })
        .collect()
}

fn package_of(krate: &str) -> Option<&'static str> {
    let dir = if krate == "xtask" {
        "xtask".to_owned()
    } else {
        format!("crates/{krate}")
    };
    workspace::PACKAGES
        .iter()
        .find(|p| p.dir == dir)
        .map(|p| p.name)
}

fn run_tests(root: &Path, krate: &str, names: &[&str], tier2: bool) -> Result<Vec<Status>, Error> {
    let Some(package) = package_of(krate) else {
        return Ok(vec![Status::Fail; names.len()]);
    };
    let mut cmd = proc::cargo_cmd(&["test", "-p", package, "--no-fail-fast", "--"]);
    if tier2 {
        cmd.arg("--include-ignored");
    }
    cmd.args(names).current_dir(root);
    let out = proc::run(&mut cmd)?;
    Ok(test_statuses(&out.stdout, names))
}

/// Gives the `(package, test binary)` pairs that a template item names, for example
/// `test:<crate>::fuzz_<target>@T1` names every `crates/*/tests/fuzz_*.rs` file.
fn expand_template(root: &Path, krate: &str, func: &str) -> Vec<(&'static str, String)> {
    let prefix = func.split('<').next().unwrap_or_default();
    let mut found = Vec::new();
    for spec in workspace::PACKAGES {
        let dir_name = spec.dir.rsplit('/').next().unwrap_or(spec.dir);
        if !krate.contains('<') && krate != dir_name {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(root.join(spec.dir).join("tests")) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned());
            if let Some(stem) = stem.filter(|s| s.starts_with(prefix))
                && path.extension().is_some_and(|x| x == "rs")
            {
                found.push((spec.name, stem));
            }
        }
    }
    found.sort();
    found
}

fn run_template(root: &Path, krate: &str, func: &str) -> Result<Status, Error> {
    let binaries = expand_template(root, krate, func);
    if binaries.is_empty() {
        return Ok(Status::Fail);
    }
    for (package, stem) in binaries {
        let mut cmd = proc::cargo_cmd(&["test", "-p", package, "--test", &stem]);
        if !proc::run(cmd.current_dir(root))?.ok() {
            return Ok(Status::Fail);
        }
    }
    Ok(Status::Pass)
}

fn run_xtask(
    root: &Path,
    sub: &str,
    cache: &mut BTreeMap<String, Option<Value>>,
) -> Result<Option<Value>, Error> {
    if let Some(value) = cache.get(sub) {
        return Ok(value.clone());
    }
    let exe = std::env::current_exe().map_err(|e| Error::io("xtask", e))?;
    let out = proc::run(Command::new(exe).arg(sub).current_dir(root))?;
    let value = json::parse(out.stdout.trim()).ok();
    cache.insert(sub.to_owned(), value.clone());
    Ok(value)
}

fn record_status(root: &Path, file: &str, pointer: &str) -> Status {
    std::fs::read_to_string(root.join(file))
        .ok()
        .and_then(|text| json::parse(&text).ok())
        .filter(|value| value.pointer(pointer).is_some())
        .map_or(Status::Fail, |_| Status::Recorded)
}

fn cmd_status(root: &Path, argv: &str) -> Result<Status, Error> {
    let mut words = argv.split_whitespace();
    let Some(program) = words.next() else {
        return Ok(Status::Fail);
    };
    let out = proc::run(Command::new(program).args(words).current_dir(root))?;
    Ok(if out.ok() { Status::Pass } else { Status::Fail })
}

/// Runs the evidence of each row. Tier-2 items run only when `tier2` is true.
///
/// # Errors
///
/// Returns an error when a process does not start.
pub fn run_rows(root: &Path, rows: &[AcRow], tier2: bool) -> Result<Vec<Outcome>, Error> {
    let mut tests: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for row in rows {
        for item in &row.evidence {
            if let Evidence::Test { krate, func, tier } = item
                && (*tier == Tier::T1 || tier2)
                && !is_template(krate, func)
            {
                tests.entry(krate.as_str()).or_default().push(func.as_str());
            }
        }
    }
    let mut test_results: BTreeMap<(String, String), Status> = BTreeMap::new();
    for (krate, names) in &tests {
        let statuses = run_tests(root, krate, names, tier2)?;
        for (name, status) in names.iter().zip(statuses) {
            test_results.insert(((*krate).to_owned(), (*name).to_owned()), status);
        }
    }
    let mut cache = BTreeMap::new();
    let mut outcomes = Vec::new();
    for row in rows {
        for item in &row.evidence {
            let status = match item {
                Evidence::Test { krate, func, tier } if is_template(krate, func) => {
                    if *tier == Tier::T1 || tier2 {
                        run_template(root, krate, func)?
                    } else {
                        Status::Skipped
                    }
                }
                Evidence::Test { krate, func, .. } => test_results
                    .get(&(krate.clone(), func.clone()))
                    .copied()
                    .unwrap_or(Status::Skipped),
                Evidence::Cmd { .. } | Evidence::Xtask { .. } if !tier2 => Status::Skipped,
                Evidence::Cmd { argv } => cmd_status(root, argv)?,
                Evidence::Xtask {
                    sub,
                    pointer,
                    op,
                    value,
                } => {
                    let report = run_xtask(root, sub, &mut cache)?;
                    let hit = report.as_ref().and_then(|r| r.pointer(pointer));
                    if hit.is_some_and(|v| compare(v, *op, value)) {
                        Status::Pass
                    } else {
                        Status::Fail
                    }
                }
                Evidence::Record { file, pointer, .. } => record_status(root, file, pointer),
            };
            outcomes.push(Outcome {
                ac: row.id.clone(),
                tier: item.tier(),
                kind: item.kind(),
                status,
            });
        }
    }
    Ok(outcomes)
}

/// Writes the evidence table with the commit of `HEAD`.
///
/// The file holds one JSON array with one row per line, so a diff shows each change.
///
/// # Errors
///
/// Returns an error when `git` or the file write fails.
pub fn write_table(root: &Path, outcomes: &[Outcome]) -> Result<Value, Error> {
    let head = proc::run_ok(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root),
    )?;
    let commit = head.stdout.trim().to_owned();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut lines = Vec::new();
    for outcome in outcomes {
        *counts.entry(outcome.status.name()).or_default() += 1;
        let tier = if outcome.tier == Tier::T1 { "T1" } else { "T2" };
        let row = Value::object([
            ("ac", Value::from(outcome.ac.as_str())),
            ("tier", Value::from(tier)),
            ("kind", Value::from(outcome.kind)),
            ("status", Value::from(outcome.status.name())),
            ("commit", Value::from(commit.as_str())),
        ]);
        lines.push(json::write(&row));
    }
    let text = format!("[\n{}\n]\n", lines.join(",\n"));
    let path = root.join(TABLE_PATH);
    std::fs::write(&path, text).map_err(|e| Error::io(&path, e))?;
    let mut summary: Vec<(&str, Value)> = counts
        .into_iter()
        .map(|(k, v)| (k, Value::from(v)))
        .collect();
    summary.push(("path", Value::from(TABLE_PATH)));
    summary.push(("commit", Value::from(commit)));
    Ok(Value::object(summary))
}
