//! The evidence table `docs/ac-evidence.json` (design Section 15, AC-018b).
//!
//! The table holds one JSON array with one row per line, so a diff shows each change.
//! A row is `{ ac, tier, kind, status, commit }`. A run with a list of ACs replaces only the
//! rows of those ACs ([`merge`]). The rows keep the order of the AC rows of the design.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use crate::ac::{AcRow, Tier};
use crate::acrun::{Outcome, Status, TABLE_PATH};
use crate::json::{self, Value};
use crate::{Error, proc};

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

/// Gives the name of a tier in the table.
const fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::T1 => "T1",
        Tier::T2 => "T2",
    }
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
        Value::object([
            ("ac", Value::from(self.ac.as_str())),
            ("tier", Value::from(tier_name(self.tier))),
            ("kind", Value::from(self.kind.as_str())),
            ("status", Value::from(self.status.name())),
            ("commit", Value::from(self.commit.as_str())),
        ])
    }

    /// Reads a row from a JSON object.
    fn from_json(value: &Value) -> Option<Self> {
        let text = |key: &str| value.get(key).and_then(Value::as_str);
        let tier = match text("tier")? {
            "T1" => Tier::T1,
            "T2" => Tier::T2,
            _ => return None,
        };
        Some(Self {
            ac: text("ac")?.to_owned(),
            tier,
            kind: text("kind")?.to_owned(),
            status: Status::parse(text("status")?)?,
            commit: text("commit")?.to_owned(),
        })
    }
}

/// Parses the text of the table.
///
/// # Errors
///
/// Returns a message when the text is not an array of rows.
pub fn parse(text: &str) -> Result<Vec<Row>, String> {
    let value = json::parse(text).map_err(|e| e.to_string())?;
    let items = value
        .as_array()
        .ok_or_else(|| "the table is not an array".to_owned())?;
    items
        .iter()
        .enumerate()
        .map(|(i, item)| Row::from_json(item).ok_or_else(|| format!("row {i} is not valid")))
        .collect()
}

/// Reads the table of the repository at `root`. A missing table gives no rows.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file exists but does not read, and [`Error::Data`] when it
/// does not parse.
pub fn read(root: &Path) -> Result<Vec<Row>, Error> {
    let path = root.join(TABLE_PATH);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    parse(&text).map_err(|e| Error::data(TABLE_PATH, e))
}

/// Merges the rows of a run into the old table.
///
/// The rows of `new` replace the old rows of each AC in `ran`. The result keeps only the ACs
/// of `design`, in design order. Inside one AC, the rows keep their order.
#[must_use]
pub fn merge(old: &[Row], ran: &BTreeSet<String>, new: &[Row], design: &[AcRow]) -> Vec<Row> {
    let mut by_ac: BTreeMap<&str, Vec<&Row>> = BTreeMap::new();
    let kept = old.iter().filter(|r| !ran.contains(&r.ac));
    for row in kept.chain(new) {
        by_ac.entry(row.ac.as_str()).or_default().push(row);
    }
    design
        .iter()
        .filter_map(|ac| by_ac.get(ac.id.as_str()))
        .flatten()
        .map(|r| (*r).clone())
        .collect()
}

/// Gives the `failed` list: one `{ ac, kind, tier }` object for each row with the status
/// `fail`.
#[must_use]
pub fn failed(rows: &[Row]) -> Value {
    let items = rows
        .iter()
        .filter(|r| r.status == Status::Fail)
        .map(|r| {
            Value::object([
                ("ac", Value::from(r.ac.as_str())),
                ("kind", Value::from(r.kind.as_str())),
                ("tier", Value::from(tier_name(r.tier))),
            ])
        })
        .collect::<Vec<_>>();
    Value::from(items)
}

/// Gives the commit of `HEAD`.
///
/// # Errors
///
/// Returns an error when `git` fails.
pub fn head_commit(root: &Path) -> Result<String, Error> {
    let head = proc::run_ok(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(root),
    )?;
    Ok(head.stdout.trim().to_owned())
}

/// Writes the table and gives a summary: the count of each status, the path and the commits.
///
/// # Errors
///
/// Returns [`Error::Io`] when the write fails.
pub fn write(root: &Path, rows: &[Row]) -> Result<Value, Error> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut commits = BTreeSet::new();
    let mut lines = Vec::new();
    for row in rows {
        *counts.entry(row.status.name()).or_default() += 1;
        commits.insert(row.commit.as_str());
        lines.push(json::write(&row.to_json()));
    }
    let text = format!("[\n{}\n]\n", lines.join(",\n"));
    let path = root.join(TABLE_PATH);
    std::fs::write(&path, text).map_err(|e| Error::io(&path, e))?;
    let mut summary: Vec<(&str, Value)> = counts
        .into_iter()
        .map(|(k, v)| (k, Value::from(v)))
        .collect();
    summary.push(("path", Value::from(TABLE_PATH)));
    let commits: Vec<Value> = commits.into_iter().map(Value::from).collect();
    summary.push(("commits", Value::from(commits)));
    Ok(Value::object(summary))
}
