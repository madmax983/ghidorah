//! The evidence runner of `xtask ac --run` and the table `docs/ac-evidence.json`.

use std::path::Path;

use crate::Error;
use crate::ac::{AcRow, Op, Tier};
use crate::json::Value;

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
    let _ = (actual, op, expected);
    false
}

/// Gives the status of each test name in libtest output.
///
/// A name matches a line `test <path> ... <result>` when `<path>` equals it or ends with `::<name>`.
#[must_use]
pub fn test_statuses(stdout: &str, names: &[&str]) -> Vec<Status> {
    let _ = (stdout, names);
    Vec::new()
}

/// Runs the evidence of each row. Tier-2 items run only when `tier2` is true.
///
/// # Errors
///
/// Returns an error when a process does not start.
pub fn run_rows(root: &Path, rows: &[AcRow], tier2: bool) -> Result<Vec<Outcome>, Error> {
    let _ = (root, rows, tier2);
    Ok(Vec::new())
}

/// Writes the evidence table with the commit of `HEAD`.
///
/// # Errors
///
/// Returns an error when `git` or the file write fails.
pub fn write_table(root: &Path, outcomes: &[Outcome]) -> Result<Value, Error> {
    let _ = (root, outcomes);
    Err(Error::data(TABLE_PATH, "writer missing"))
}
