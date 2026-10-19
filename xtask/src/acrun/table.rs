//! The evidence table `docs/ac-evidence.json` (design Section 15, AC-018b).
//!
//! The table holds one JSON array with one row per line, so a diff shows each change.
//! A row is `{ ac, tier, kind, status, commit }`. A run with a list of ACs replaces only the
//! rows of those ACs ([`merge`]). The rows keep the order of the AC rows of the design.

use std::collections::BTreeSet;
use std::path::Path;

use crate::Error;
use crate::ac::{AcRow, Tier};
use crate::acrun::{Outcome, Status};
use crate::json::Value;

/// One row of the evidence table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The AC ID.
    pub ac: String,
    /// The tier of the item.
    pub tier: Tier,
    /// The kind name of the item: `test`, `cmd`, `xtask` or `record`.
    pub kind: String,
    /// The status.
    pub status: Status,
    /// The commit of the run.
    pub commit: String,
}

impl Row {
    /// Makes the row of an outcome of the run at `commit`.
    #[must_use]
    pub fn new(outcome: &Outcome, commit: &str) -> Self {
        Self {
            ac: outcome.ac.clone(),
            tier: outcome.tier,
            kind: outcome.kind.to_owned(),
            status: outcome.status,
            commit: commit.to_owned(),
        }
    }

    /// Gives the row as a JSON object.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Null
    }
}

/// Parses the text of the table.
///
/// # Errors
///
/// Returns a message when the text is not an array of rows.
pub fn parse(text: &str) -> Result<Vec<Row>, String> {
    let _ = text;
    Ok(Vec::new())
}

/// Reads the table of the repository at `root`. A missing table gives no rows.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file exists but does not read, and [`Error::Data`] when it
/// does not parse.
pub fn read(root: &Path) -> Result<Vec<Row>, Error> {
    let _ = root;
    Ok(Vec::new())
}

/// Merges the rows of a run into the old table.
///
/// The rows of `new` replace the old rows of each AC in `ran`. The result keeps only the ACs
/// of `design`, in design order. Inside one AC, the rows keep their order.
#[must_use]
pub fn merge(old: &[Row], ran: &BTreeSet<String>, new: &[Row], design: &[AcRow]) -> Vec<Row> {
    let _ = (old, ran, new, design);
    Vec::new()
}

/// Gives the `failed` list: one `{ ac, kind, tier }` object for each row with the status
/// `fail`.
#[must_use]
pub fn failed(rows: &[Row]) -> Value {
    let _ = rows;
    Value::Array(Vec::new())
}

/// Gives the commit of `HEAD`.
///
/// # Errors
///
/// Returns an error when `git` fails.
pub fn head_commit(root: &Path) -> Result<String, Error> {
    let _ = root;
    Ok(String::new())
}

/// Writes the table and gives a summary: the count of each status, the path and the commits.
///
/// # Errors
///
/// Returns [`Error::Io`] when the write fails.
pub fn write(root: &Path, rows: &[Row]) -> Result<Value, Error> {
    let _ = (root, rows);
    Ok(Value::Null)
}
