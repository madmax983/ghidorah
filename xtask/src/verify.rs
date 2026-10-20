//! The `xtask verify` command: the Verus proofs of the kernel (design Sections 13.1 to 13.3).
//!
//! The command finds Verus in `VERUS`, else as `verus` on `PATH`. `VERUS_Z3_PATH` names z3.
//! For each kernel of [`KERNELS`], it runs Verus with `--verify-module <module>`.
//! A kernel gets the status `verified` only when Verus gives no error and lists each
//! `#[verus_spec]` function.
//!
//! Then the command applies each negative patch of each kernel to a copy of the kernel and runs
//! Verus again. A negative run must fail with the expected error of its patch, one of
//! [`VERIFY_ERRORS`], and at least one verified item.
//! A good run writes [`RESULTS_PATH`]. A failed run writes [`FAILED_PATH`] and keeps
//! [`RESULTS_PATH`], so the record always holds a good run. The command prints the written
//! object with `ok`, `status` and `results`, the path of the written file.
//!
//! Without Verus, the command fails. With `GHIDORAH_VERUS_OPTIONAL=1`, it prints
//! `{ "ok": true, "status": "skipped" }` and exits with code 0.
//!
//! Record: `{ verus_commit, toolchain, z3, argv, tree_sha256, kernels: { <name>: { name, file,
//! module, verified, errors, spec_items, status } }, negatives: [{ kernel, patch, error_kind,
//! verified, errors, ok }] }`.

mod kernels;
pub mod patch;
mod run;
pub mod tree;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub use kernels::{
    ASSERTION, KERNELS, Kernel, Negative, POSTCONDITION, PRECONDITION, VERIFY_ERRORS,
};
pub use tree::{ARGV, RESULTS_PATH, tree_sha256};

use crate::json::{self, Value};
use crate::{Error, rustsrc};

/// The record of a failed run, relative to the workspace root. A good run removes it.
pub const FAILED_PATH: &str = "verify/results.failed.json";

/// The environment values of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// The Verus program, or `None` when no Verus is available.
    pub verus: Option<PathBuf>,
    /// The z3 program of `VERUS_Z3_PATH`.
    pub z3: Option<PathBuf>,
    /// `GHIDORAH_VERUS_OPTIONAL=1`: a run without Verus gives `skipped`.
    pub optional: bool,
}

impl Settings {
    /// Reads `VERUS`, `PATH`, `VERUS_Z3_PATH` and `GHIDORAH_VERUS_OPTIONAL`.
    #[must_use]
    pub fn from_env() -> Self {
        let non_empty = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
        let verus = non_empty("VERUS")
            .map(PathBuf::from)
            .or_else(|| find_on_path("verus", non_empty("PATH").as_deref()));
        Self {
            verus,
            z3: non_empty("VERUS_Z3_PATH").map(PathBuf::from),
            optional: std::env::var("GHIDORAH_VERUS_OPTIONAL").is_ok_and(|v| v == "1"),
        }
    }
}

/// The counts of one Verus run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// The count of verified items.
    pub verified: u64,
    /// The count of failed items.
    pub errors: u64,
    /// Verus reports success.
    pub success: bool,
}

/// The versions of the tools of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tools {
    /// The first 7 digits of the Verus commit.
    pub verus_commit: String,
    /// The Rust toolchain of Verus, for example `1.98.1`.
    pub toolchain: String,
    /// The z3 version, for example `4.16.0`.
    pub z3: String,
}

/// The text of a missing tool version.
const UNKNOWN: &str = "unknown";

/// The message of a run without Verus.
const NO_VERUS: &str = "no Verus binary: set VERUS or put `verus` on PATH";

/// Parses the JSON object of Verus output. Text before the first `{` does not count.
fn verus_json(stdout: &str) -> Option<Value> {
    let start = stdout.find('{')?;
    json::parse(stdout.get(start..)?.trim()).ok()
}

/// Reads the counts from the JSON output of `verus --output-json`.
///
/// Without a `success` member, the run succeeds when it has no error.
///
/// # Errors
///
/// Gives [`Error::Data`] when the output has no `verification-results` object.
pub fn parse_counts(stdout: &str) -> Result<Counts, Error> {
    let value = verus_json(stdout).ok_or_else(|| Error::data("verus", "no JSON output"))?;
    let results = value
        .get("verification-results")
        .filter(|v| v.as_object().is_some())
        .ok_or_else(|| Error::data("verus", "no verification-results object"))?;
    let number = |key: &str| results.get(key).and_then(Value::as_u64).unwrap_or(0);
    let flag = |key: &str| results.get(key).and_then(Value::as_bool);
    let errors = number("errors");
    // A run with `--verify-module` has no `success` member. Then no error means success.
    let success =
        flag("success").unwrap_or_else(|| flag("encountered-error") == Some(false) && errors == 0);
    Ok(Counts {
        verified: number("verified"),
        errors,
        success,
    })
}

/// Reads the Verus commit and toolchain from the JSON output of `verus --output-json`.
///
/// `z3_version` is the output of `z3 --version`. A missing value gives `unknown`.
#[must_use]
pub fn parse_tools(stdout: &str, z3_version: &str) -> Tools {
    let value = verus_json(stdout);
    let field = |key: &str| {
        value
            .as_ref()
            .and_then(|v| v.pointer(&format!("/verus/{key}")))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    let z3 = z3_version
        .split_whitespace()
        .skip_while(|w| *w != "version")
        .nth(1)
        .unwrap_or(UNKNOWN);
    Tools {
        verus_commit: field("commit")
            .map_or(UNKNOWN, |c| c.get(..7).unwrap_or(c))
            .to_owned(),
        toolchain: field("toolchain")
            .and_then(|t| t.split(['-', ' ']).next())
            .unwrap_or(UNKNOWN)
            .to_owned(),
        z3: z3.to_owned(),
    }
}

/// Gives the first verification error of [`VERIFY_ERRORS`] in the Verus error output.
#[must_use]
pub fn error_kind(stderr: &str) -> Option<&'static str> {
    stderr.lines().find_map(|line| {
        let message = line.trim().strip_prefix("error: ")?;
        VERIFY_ERRORS
            .iter()
            .copied()
            .find(|kind| message.starts_with(kind))
    })
}

/// Gives the count of `#[verus_spec(..)]` items in a source text. Comments do not count.
///
/// The loop form `#[cfg_attr(verus_only, verus_spec(..))]` does not count.
#[must_use]
pub fn spec_items(text: &str) -> u64 {
    let count = rustsrc::strip(text).matches("#[verus_spec(").count();
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// Gives the text after the attribute at the start of `code`, or `None` without a closing `]`.
fn after_attribute(code: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (i, c) in code.char_indices() {
        match c {
            '[' => depth = depth.saturating_add(1),
            ']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return code.get(i.saturating_add(1)..);
                }
            }
            _ => {}
        }
    }
    None
}

/// Gives the name of the function that a text before its body declares, or `None`.
fn fn_name(signature: &str) -> Option<String> {
    let head = signature.split(['{', ';']).next().unwrap_or_default();
    let words: Vec<&str> = head
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    let at = words.iter().position(|w| *w == "fn")?;
    words.get(at.saturating_add(1)).map(|w| (*w).to_owned())
}

/// Gives the function name of each `#[verus_spec(..)]` item in a source text, in source order.
///
/// Comments and strings do not count. A spec item without a function gives no name.
#[must_use]
pub fn spec_functions(text: &str) -> Vec<String> {
    let code = rustsrc::strip(text);
    code.match_indices("#[verus_spec(")
        .filter_map(|(at, _)| {
            let attribute = code.get(at.saturating_add(1)..)?;
            fn_name(after_attribute(attribute)?)
        })
        .collect()
}

/// Gives the names of the `func-details` object of the JSON output of `verus --output-json`.
///
/// Verus lists each function that it verifies. It does not list an `external` function.
/// A name with a failed proof note does not count. Output without the object gives `None`.
#[must_use]
pub fn parse_functions(stdout: &str) -> Option<Vec<String>> {
    let value = verus_json(stdout)?;
    let details = value.get("func-details")?.as_object()?;
    let failed = |detail: &Value| {
        detail
            .get("failed_proof_notes")
            .and_then(Value::as_array)
            .is_some_and(|notes| !notes.is_empty())
    };
    Some(
        details
            .iter()
            .filter(|(_, detail)| !failed(detail))
            .map(|(name, _)| name.clone())
            .collect(),
    )
}

/// Gives each spec function of a kernel that has no entry in the Verus output.
///
/// An entry `<crate>::<module>::..::<name>` proves one function `name` of the kernel `module`.
/// Two spec functions with one name need two entries. The result keeps the order of `spec`.
#[must_use]
pub fn unproved(module: &str, spec: &[String], proved: &[String]) -> Vec<String> {
    let mut left: Vec<&str> = proved
        .iter()
        .filter(|name| name.split("::").nth(1) == Some(module))
        .filter_map(|name| name.rsplit("::").next())
        .collect();
    let mut missing = Vec::new();
    for name in spec {
        match left.iter().position(|have| *have == name) {
            Some(at) => {
                left.swap_remove(at);
            }
            None => missing.push(name.clone()),
        }
    }
    missing
}

/// Finds `name` in the directories of a `PATH` value.
#[must_use]
pub fn find_on_path(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path?)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Runs the command with the settings of the environment.
///
/// # Errors
///
/// Gives [`Error::Usage`] for an argument, and the errors of [`run_with`].
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    if let Some(arg) = args.first() {
        return Err(Error::Usage(format!(
            "cargo xtask verify (no argument expected, got `{arg}`)"
        )));
    }
    run_with(root, &Settings::from_env())
}

/// Runs the proofs and the negative patches with `settings`, and writes [`RESULTS_PATH`].
///
/// # Errors
///
/// Gives [`Error::Io`] for a failed file operation and [`Error::Command`] when Verus does not start.
pub fn run_with(root: &Path, settings: &Settings) -> Result<Value, Error> {
    let Some(verus) = &settings.verus else {
        let (ok, status, key) = if settings.optional {
            (true, "skipped", "reason")
        } else {
            (false, "missing", "error")
        };
        return Ok(Value::object([
            ("ok", Value::from(ok)),
            ("status", Value::from(status)),
            (key, Value::from(NO_VERUS)),
        ]));
    };
    run::proofs(root, verus, settings.z3.as_deref())
}
