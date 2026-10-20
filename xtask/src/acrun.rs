//! The evidence runner of `xtask ac --run` and the table `docs/ac-evidence.json`.
//!
//! Tier-1 test items always run. Tier-2 test items, `cmd:` items and `xtask:` items run only
//! with `--tier2`. Test items run with `GHIDORAH_REQUIRE_PROOFS=1`. A `record:` item gives `recorded` when its hash matches its named input
//! ([`record`]). The module [`table`] reads, merges and writes the evidence table.

pub mod record;
pub mod table;

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
    /// The record matches the hash of its named input.
    Recorded,
    /// The item did not run in this tier, or the record check gives no verdict on this host
    /// ([`record`]).
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

    /// Gives the status of a name of the table.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Pass, Self::Fail, Self::Recorded, Self::Skipped]
            .into_iter()
            .find(|s| s.name() == name)
    }
}

/// Tells if an item is an `xtask:ac` item. Such an item reads the table of its own run.
#[must_use]
pub fn is_self(item: &Evidence) -> bool {
    matches!(item, Evidence::Xtask { sub, .. } if sub == "ac")
}

/// Splits the rows into the rows without `xtask:ac` items and the rows with only those items.
/// A row without items of a part does not appear in that part.
#[must_use]
pub fn split_self(rows: &[AcRow]) -> (Vec<AcRow>, Vec<AcRow>) {
    let part = |own: bool| -> Vec<AcRow> {
        rows.iter()
            .filter_map(|row| {
                let evidence: Vec<Evidence> = row
                    .evidence
                    .iter()
                    .filter(|item| is_self(item) == own)
                    .cloned()
                    .collect();
                (!evidence.is_empty()).then(|| AcRow {
                    evidence,
                    ..row.clone()
                })
            })
            .collect()
    };
    (part(false), part(true))
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

/// Gives a cargo command of an evidence run.
///
/// The command sets `GHIDORAH_REQUIRE_PROOFS=1`, as `xtask ci` does (ADR-0011).
/// So a stale proof record fails `ac_034_proof_freshness`. It does not give `pass` with a warning.
fn evidence_cargo(root: &Path, args: &[&str]) -> Command {
    let mut cmd = proc::cargo_cmd(args);
    cmd.env("GHIDORAH_REQUIRE_PROOFS", "1").current_dir(root);
    cmd
}

/// Gives the command that runs the named tests of `package` for the evidence table.
///
/// With `tier2`, the command also runs the ignored tests.
#[must_use]
pub fn test_command(root: &Path, package: &str, names: &[&str], tier2: bool) -> Command {
    let mut cmd = evidence_cargo(root, &["test", "-p", package, "--no-fail-fast", "--"]);
    if tier2 {
        cmd.arg("--include-ignored");
    }
    cmd.args(names);
    cmd
}

fn run_tests(root: &Path, krate: &str, names: &[&str], tier2: bool) -> Result<Vec<Status>, Error> {
    let Some(package) = package_of(krate) else {
        return Ok(vec![Status::Fail; names.len()]);
    };
    let out = proc::run(&mut test_command(root, package, names, tier2))?;
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
        let mut cmd = evidence_cargo(root, &["test", "-p", package, "--test", &stem]);
        if !proc::run(&mut cmd)?.ok() {
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
    // Cargo runs the xtask command. The running binary can be a test binary.
    // Also, a cargo step of the same run can build `target/debug/xtask` again.
    let mut cmd = proc::cargo_cmd(&["run", "--quiet", "--package", "xtask", "--", sub]);
    let out = proc::run(cmd.current_dir(root))?;
    let value = json::parse(out.stdout.trim()).ok();
    cache.insert(sub.to_owned(), value.clone());
    Ok(value)
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
                Evidence::Record {
                    file,
                    pointer,
                    input,
                } => {
                    // An evidence run requires proofs, as its test items do.
                    record::status(root, file, pointer, input, true)
                }
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
