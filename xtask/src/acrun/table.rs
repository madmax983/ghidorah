//! The evidence table `docs/ac-evidence.json` (design Section 15, AC-018b).
//!
//! The table holds one JSON array with one row per line, so a diff shows each change.
//! A row is `{ ac, tier, kind, status, commit }`. A run with a list of ACs replaces only the
//! rows of those ACs ([`merge`]). The rows keep the order of the AC rows of the design.
//! [`failed`], [`stale`] and [`not_passed`] give the lists of the `xtask ac` report (AC-018b).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use crate::ac::{AcRow, Evidence, Tier};
use crate::acrun::{Outcome, Status, TABLE_PATH, is_self};
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

/// Gives each evidence item of the MVP rows of `design` with its table row, or `None` when the
/// item has no row. The `xtask:ac` items do not take part, because their rows come after them.
///
/// A row does not name its item. So the rows of one AC match the items of the same kind and
/// tier in order. The `xtask:ac` items run last, so a row after the other items of its kind
/// and tier is the row of an `xtask:ac` item.
fn item_rows<'a>(
    rows: &'a [Row],
    design: &'a [AcRow],
) -> Vec<(&'a str, &'a Evidence, Option<&'a Row>)> {
    let mut found = Vec::new();
    for ac in design.iter().filter(|r| r.is_gate()) {
        let mut used: BTreeMap<(&str, Tier), usize> = BTreeMap::new();
        for item in ac.evidence.iter().filter(|item| !is_self(item)) {
            let key = (item.kind(), item.tier());
            let seen = used.entry(key).or_default();
            let row = rows
                .iter()
                .filter(|r| r.ac == ac.id && r.kind == key.0 && r.tier == key.1)
                .nth(*seen);
            *seen += 1;
            found.push((ac.id.as_str(), item, row));
        }
    }
    found
}

/// The largest number of row commits that [`fresh_commits`] compares with `HEAD`.
pub const MAX_COMPARED: usize = 64;

/// Tells if `text` can be a commit name: 4 to 64 hex digits. Another text never goes to `git`.
fn is_commit_name(text: &str) -> bool {
    (4..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Tells if the trees of `commit` and `head` are equal outside the table.
fn same_tree(root: &Path, commit: &str, head: &str) -> bool {
    let mut cmd = Command::new("git");
    cmd.args(["diff", "--quiet", "--no-ext-diff", commit, head, "--", "."])
        .arg(format!(":(exclude){TABLE_PATH}"))
        .current_dir(root);
    proc::run(&mut cmd).is_ok_and(|out| out.ok())
}

/// Gives the fresh commits of `rows` at `head`. The `stale` list holds the rows of the other
/// commits.
///
/// `head` is fresh. Another commit is fresh when its tree and the tree of `head` are equal
/// outside the table. So the commit that writes the table does not make the rows of its run
/// stale. Each distinct commit takes one `git diff --quiet` call, for at most
/// [`MAX_COMPARED`] commits. An unknown commit, a failed call, a text that is not a commit
/// name and a commit after the bound are not fresh.
#[must_use]
pub fn fresh_commits(root: &Path, rows: &[Row], head: &str) -> BTreeSet<String> {
    let mut fresh = BTreeSet::new();
    if !is_commit_name(head) {
        return fresh;
    }
    let others: BTreeSet<&str> = rows
        .iter()
        .map(|r| r.commit.as_str())
        .filter(|c| *c != head && is_commit_name(c))
        .collect();
    for commit in others.into_iter().take(MAX_COMPARED) {
        if same_tree(root, commit, head) {
            fresh.insert(commit.to_owned());
        }
    }
    fresh.insert(head.to_owned());
    fresh
}

/// Gives the `stale` list: one `{ ac, kind, tier, commit }` object for each row of an
/// evidence item whose commit is not in `fresh`. The rows of `xtask:ac` items do not count.
#[must_use]
pub fn stale(rows: &[Row], design: &[AcRow], fresh: &BTreeSet<String>) -> Value {
    let items = item_rows(rows, design)
        .into_iter()
        .filter_map(|(_, _, row)| row.filter(|r| !fresh.contains(&r.commit)))
        .map(|r| {
            Value::object([
                ("ac", Value::from(r.ac.as_str())),
                ("kind", Value::from(r.kind.as_str())),
                ("tier", Value::from(tier_name(r.tier))),
                ("commit", Value::from(r.commit.as_str())),
            ])
        })
        .collect::<Vec<_>>();
    Value::from(items)
}

/// Gives the `not_passed` list of the evidence items that do not pass.
///
/// Each `test`, `cmd` or `xtask` row that is not `pass` gives one `{ ac, kind, tier, status }`
/// object. Each evidence item without a row also gives an object, with the status `missing`.
/// The `xtask:ac` items do not count.
#[must_use]
pub fn not_passed(rows: &[Row], design: &[AcRow]) -> Value {
    let items = item_rows(rows, design)
        .into_iter()
        .filter_map(|(ac, item, row)| {
            let status = match row {
                None => "missing",
                Some(r) if r.kind != "record" && r.status != Status::Pass => r.status.name(),
                Some(_) => return None,
            };
            Some(Value::object([
                ("ac", Value::from(ac)),
                ("kind", Value::from(item.kind())),
                ("tier", Value::from(tier_name(item.tier()))),
                ("status", Value::from(status)),
            ]))
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
