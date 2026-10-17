//! The `xtask verify` command: the Verus proofs of the kernel (design Sections 13.1 to 13.3).
//!
//! The command finds Verus in `VERUS`, else as `verus` on `PATH`. `VERUS_Z3_PATH` names z3.
//! For each kernel of [`KERNELS`], it runs Verus with `--verify-module <module>`.
//! Then it applies the negative patch of each kernel to a copy of the kernel and runs Verus again.
//! A negative run must fail with a verification error and at least one verified item.
//! The command writes [`RESULTS_PATH`] and prints the same object with `ok` and `status`.
//!
//! Without Verus, the command fails. With `GHIDORAH_VERUS_OPTIONAL=1`, it prints
//! `{ "ok": true, "status": "skipped" }` and exits with code 0.
//!
//! Record: `{ verus_commit, toolchain, z3, argv, tree_sha256, kernels: { <name>: { name, file,
//! module, verified, errors, spec_items, status } }, negatives: [{ kernel, patch, error_kind,
//! verified, errors, ok }] }`.

pub mod patch;
mod run;
pub mod tree;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub use tree::{ARGV, RESULTS_PATH, tree_sha256};

use crate::json::{self, Value};
use crate::{Error, rustsrc};

/// One kernel of design Section 13.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kernel {
    /// The kernel name, for example `K1`.
    pub name: &'static str,
    /// The module of the kernel in `ghidorah-kernel`.
    pub module: &'static str,
}

impl Kernel {
    /// Gives the main source file of the kernel, relative to the workspace root.
    #[must_use]
    pub fn file(&self) -> String {
        format!("crates/kernel/src/{}.rs", self.module)
    }

    /// Gives the directory of the submodules of the kernel, relative to the workspace root.
    #[must_use]
    pub fn dir(&self) -> String {
        format!("crates/kernel/src/{}", self.module)
    }

    /// Gives the negative patch of the kernel, relative to the workspace root.
    #[must_use]
    pub fn patch(&self) -> String {
        format!("verify/negative/{}.patch", self.name)
    }
}

/// The kernels that `xtask verify` proves, in name order.
pub const KERNELS: &[Kernel] = &[
    Kernel {
        name: "K1",
        module: "reader",
    },
    Kernel {
        name: "K2",
        module: "range",
    },
    Kernel {
        name: "K3",
        module: "rangeset",
    },
    Kernel {
        name: "K6",
        module: "budget",
    },
    Kernel {
        name: "K7",
        module: "source",
    },
];

/// The Verus messages that count as a verification error of a negative run.
pub const VERIFY_ERRORS: &[&str] = &[
    "postcondition not satisfied",
    "assertion failed",
    "precondition not satisfied",
];

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
