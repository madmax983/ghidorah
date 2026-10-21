//! The `xtask golden` command: bless goldens and check their headers (design Section 13.7).
//!
//! | Command | Effect |
//! |---|---|
//! | `xtask golden bless [cargo test args]` | Runs `cargo test --workspace` with `GHIDORAH_BLESS=1`. Prints the count of changed golden files per area. |
//! | `xtask golden headers` | Checks the golden headers against `fixtures/manifest.json` (AC-022). |
//! | `xtask golden x86` | Runs the `ghidorah-x86` golden tests and their tier-2 oracle tests with `GHIDORAH_BLESS=1` (Section 13.8). |
//!
//! An area is the first directory under `tests/golden`, for example `loader`. A file at the top
//! of `tests/golden` has the area `.`. The command sets the bless variable only for its child
//! `cargo` process (ADR-0012).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::fixtures::manifest;
use crate::json::Value;
use crate::verify::tree::sha256;
use crate::workspace::rel;
use crate::{Error, Finding, proc};

/// The golden root, relative to the workspace root.
pub const ROOT: &str = "tests/golden";

/// The cargo arguments of `xtask golden x86`.
///
/// The `x86` test binary writes `tests/golden/x86_text` again. Its tier-2 tests compare
/// `tests/golden/x86_len` and `tests/data/x86_spec.txt` with `llvm-objdump` and GNU `objdump`.
pub const X86_ARGS: &[&str] = &[
    "test",
    "-p",
    "ghidorah-x86",
    "--test",
    "x86",
    "--",
    "--include-ignored",
];

/// The depth limit of the directory walk.
const MAX_DEPTH: usize = 8;

/// The hash of each golden file, keyed by its path relative to the workspace root.
pub type Snapshot = BTreeMap<String, [u8; 32]>;

fn walk(root: &Path, dir: &Path, depth: usize, out: &mut Snapshot) -> Result<(), Error> {
    if depth > MAX_DEPTH || !dir.is_dir() {
        return Ok(());
    }
    for item in std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))? {
        let path = item.map_err(|e| Error::io(dir, e))?.path();
        if path.is_dir() {
            walk(root, &path, depth + 1, out)?;
        } else {
            let bytes = std::fs::read(&path).map_err(|e| Error::io(&path, e))?;
            out.insert(rel(root, &path), sha256(&bytes));
        }
    }
    Ok(())
}

/// Gives the hash of each golden file of the workspace.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file or a directory does not read.
pub fn snapshot(root: &Path) -> Result<Snapshot, Error> {
    let mut out = Snapshot::new();
    walk(root, &root.join(ROOT), 0, &mut out)?;
    Ok(out)
}

/// Gives the area of a golden path: `tests/golden/loader/x.txt` gives `loader`.
#[must_use]
pub fn area(path: &str) -> &str {
    let rest = path
        .strip_prefix(ROOT)
        .and_then(|r| r.strip_prefix('/'))
        .unwrap_or(path);
    match rest.split_once('/') {
        Some((first, _)) => first,
        None => ".",
    }
}

/// Gives the count of added, removed and changed files per area between two snapshots.
#[must_use]
pub fn changes(before: &Snapshot, after: &Snapshot) -> BTreeMap<String, u64> {
    let paths: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let mut out: BTreeMap<String, u64> = BTreeMap::new();
    for path in paths {
        if before.get(path) != after.get(path) {
            *out.entry(area(path).to_owned()).or_default() += 1;
        }
    }
    out
}

fn bless(root: &Path, extra: &[String]) -> Result<Value, Error> {
    let mut args = vec!["test", "--workspace"];
    args.extend(extra.iter().map(String::as_str));
    bless_run(root, &args)
}

fn bless_run(root: &Path, args: &[&str]) -> Result<Value, Error> {
    let before = snapshot(root)?;
    let mut cmd = proc::cargo_cmd(args);
    cmd.current_dir(root)
        .env(ghidorah_testkit::golden::BLESS_ENV, "1");
    let out = proc::run(&mut cmd)?;
    let after = snapshot(root)?;
    let areas: BTreeMap<String, Value> = changes(&before, &after)
        .into_iter()
        .map(|(k, v)| (k, Value::from(v)))
        .collect();
    Ok(Value::object([
        ("ok", Value::from(out.ok())),
        ("tests_ok", Value::from(out.ok())),
        ("changed", Value::Object(areas)),
    ]))
}

/// Runs `xtask golden <bless|headers|x86>`.
///
/// # Errors
///
/// Returns [`Error::Usage`] for an unknown command, or the error of the command.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    match args.split_first() {
        Some((cmd, rest)) if cmd == "bless" => bless(root, rest),
        Some((cmd, [])) if cmd == "x86" => bless_run(root, X86_ARGS),
        Some((cmd, [])) if cmd == "headers" => {
            let found = manifest::check_goldens(root, &manifest::read(root)?)?;
            Ok(Value::object([
                ("ok", Value::from(found.is_empty())),
                (
                    "findings",
                    Value::from(found.iter().map(Finding::to_json).collect::<Vec<_>>()),
                ),
            ]))
        }
        _ => Err(Error::Usage(
            "cargo xtask golden <bless [cargo test args]|headers|x86>".to_owned(),
        )),
    }
}
