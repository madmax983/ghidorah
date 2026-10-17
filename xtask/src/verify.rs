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
pub mod tree;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub use tree::{ARGV, RESULTS_PATH, tree_sha256};

use crate::Error;
use crate::json::Value;

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
        String::new()
    }

    /// Gives the negative patch of the kernel, relative to the workspace root.
    #[must_use]
    pub fn patch(&self) -> String {
        String::new()
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
        Self::default()
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

/// Reads the counts from the JSON output of `verus --output-json`.
///
/// # Errors
///
/// Gives [`Error::Data`] when the output has no `verification-results` object.
pub fn parse_counts(stdout: &str) -> Result<Counts, Error> {
    let _ = stdout;
    Err(Error::data("verus", "no verification results"))
}

/// Reads the Verus commit and toolchain from the JSON output of `verus --output-json`.
///
/// A missing value gives `unknown`.
#[must_use]
pub fn parse_tools(stdout: &str, z3_version: &str) -> Tools {
    let _ = (stdout, z3_version);
    Tools::default()
}

/// Gives the first verification error of [`VERIFY_ERRORS`] in the Verus error output.
#[must_use]
pub fn error_kind(stderr: &str) -> Option<&'static str> {
    let _ = stderr;
    None
}

/// Gives the count of `#[verus_spec(..)]` items in a source text. Comments do not count.
///
/// The loop form `#[cfg_attr(verus_only, verus_spec(..))]` does not count.
#[must_use]
pub fn spec_items(text: &str) -> u64 {
    let _ = text;
    0
}

/// Finds `name` in the directories of a `PATH` value.
#[must_use]
pub fn find_on_path(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let _ = (name, path);
    None
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
/// Gives [`Error::Io`] for a failed file operation, [`Error::Command`] when Verus does not start,
/// and [`Error::Data`] for a bad patch or bad Verus output.
pub fn run_with(root: &Path, settings: &Settings) -> Result<Value, Error> {
    let _ = (root, settings);
    Ok(Value::object([("ok", Value::from(false))]))
}
