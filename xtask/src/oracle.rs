//! The `xtask oracle` command: host oracles for the x86 crate (design Section 13.8).
//!
//! | Command | Effect |
//! |---|---|
//! | `xtask oracle semantics` | Runs each form of `ghidorah-oracle` in a child process and writes `tests/golden/semantics/x86/<file>.jsonl`. |
//! | `xtask oracle semantics --check` | Runs the forms and compares the result with the checked-in files. Writes no file. |
//! | `xtask oracle bash` | Runs the tier-2 host boundary test of `ghidorah-x86` on host bash and libc and writes `verify/oracle-results.json` (AC-066). |
//!
//! The vector files hold host evidence. Their header names the CPU model, so a run on
//! another CPU can differ in the flags that the hardware leaves undefined.

use std::collections::BTreeMap;
use std::path::Path;

use crate::Error;
use crate::json::Value;

/// The vector directory, relative to the workspace root.
pub const SEMANTICS_DIR: &str = "tests/golden/semantics/x86";

/// The record of the host boundary oracle, relative to the workspace root.
pub const RECORD: &str = "verify/oracle-results.json";

/// The generator name in the headers.
pub const GENERATOR: &str = "xtask-oracle";

/// The generator version in the headers.
pub const VERSION: &str = "1";

/// The prefix of the result line that the host boundary test prints.
pub const RESULT_PREFIX: &str = "oracle-result ";

/// The cargo arguments of the host boundary test.
pub const BASH_TEST: &[&str] = &[
    "test",
    "-p",
    "ghidorah-x86",
    "--test",
    "x86",
    "--",
    "--ignored",
    "--exact",
    "host::tier2_host_boundaries",
    "--nocapture",
];

/// Gives the CPU model of `/proc/cpuinfo` text, or `unknown`.
#[must_use]
pub fn cpu_model(cpuinfo: &str) -> String {
    let _ = cpuinfo;
    String::new()
}

/// Parses the output of `ghidorah-oracle list` into `(file, form name)` pairs.
///
/// # Errors
///
/// Returns [`Error::Data`] for a line without a tab or a file name that is not a plain name.
pub fn parse_list(text: &str) -> Result<Vec<(String, String)>, Error> {
    let _ = text;
    Ok(Vec::new())
}

/// Gives the text of each vector file: the header line, then the output of each form in
/// list order.
///
/// `outputs` holds the output of `ghidorah-oracle form <name>` for each item of `list`.
#[must_use]
pub fn render_files(
    cpu: &str,
    list: &[(String, String)],
    outputs: &[String],
) -> BTreeMap<String, String> {
    let _ = (cpu, list, outputs);
    BTreeMap::new()
}

/// Makes the record of the host boundary oracle from the output of its test.
///
/// # Errors
///
/// Returns [`Error::Data`] when the output has no result line or the line is not JSON.
pub fn bash_record(test_stdout: &str) -> Result<Value, Error> {
    let _ = test_stdout;
    Err(Error::data("oracle bash", "no result line"))
}

/// Runs `xtask oracle <semantics [--check]|bash>`.
///
/// # Errors
///
/// Returns [`Error::Usage`] for bad arguments, [`Error::Command`] when a child process
/// fails and [`Error::Io`] when a file does not read or write.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let _ = (root, args);
    Err(Error::Usage(
        "cargo xtask oracle <semantics [--check]|bash>".to_owned(),
    ))
}
