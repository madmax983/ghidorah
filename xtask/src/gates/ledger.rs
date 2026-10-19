//! The license ledger gate of WP-28 (design Section 15.3): AC-027.
//!
//! [`NOTICE`] and [`LEDGER`] list each vendored data file. Each data file names its source and
//! its license.
//!
//! - A data file is a file under `crates/*/data/`, `crates/*/tests/data/` or `tests/data/`.
//!   A `LICENSE` file, a Markdown file and a dot file are not data.
//! - A vendored data file has a header that names a copyright holder other than ghidorah.
//!   Each file in a directory with a `LICENSE` file is also a vendored file.
//! - Each text file under `crates/*/data/` names its source and its license in its header.
//!   The header is the first [`HEADER_LINES`] lines. Each text file of a ledger row obeys the same rule.
//! - A JSON file or a binary file of a ledger row uses the `README.md` of its directory.
//! - An embedded binary file of ghidorah names its source in its Rust module.
//!   An example is `crates/tools/data/demo.elf`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::docs::{cells, first_code, has_extension, read};
use crate::{Error, Finding};

/// The license ledger.
pub const LEDGER: &str = "docs/licenses.md";

/// The attribution file.
pub const NOTICE: &str = "NOTICE";

/// The number of lines of a data file that make its header.
pub const HEADER_LINES: usize = 12;

/// The maximum depth of a data directory walk.
const MAX_DEPTH: usize = 8;

/// The maximum number of data files that one walk reads.
const MAX_FILES: usize = 20_000;

/// One row of the license ledger table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRow {
    /// The path pattern of the file column. Only the file name can hold `*`.
    pub pattern: String,
    /// The text of the source column.
    pub source: String,
    /// The text of the license column.
    pub license: String,
    /// The 1-based line in the ledger.
    pub line: usize,
}

/// One data file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFile {
    /// The path relative to the workspace root, with `/` separators.
    pub path: String,
    /// The first [`HEADER_LINES`] lines, or `None` when the file is not UTF-8 text.
    pub head: Option<String>,
}

/// Gives the rows of the license ledger table.
#[must_use]
pub fn ledger_rows(ledger: &str) -> Vec<LedgerRow> {
    let mut rows = Vec::new();
    for (i, line) in ledger.lines().enumerate() {
        if !line.starts_with("| `") {
            continue;
        }
        let parts = cells(line);
        let Some(pattern) = parts.first().and_then(|c| first_code(c)) else {
            continue;
        };
        rows.push(LedgerRow {
            pattern: pattern.to_owned(),
            source: parts.get(1).copied().unwrap_or_default().to_owned(),
            license: parts.get(2).copied().unwrap_or_default().to_owned(),
            line: i + 1,
        });
    }
    rows
}

/// Tells if the name `text` matches the name pattern `pattern` with `*` wildcards.
fn name_match(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let tail: Vec<&str> = parts.collect();
    let Some((last, middle)) = tail.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = rest.get(at + part.len()..).unwrap_or_default(),
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// Tells if `path` matches `pattern`. A `*` matches any run of characters except `/`.
#[must_use]
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let (pattern_dir, pattern_name) = pattern.rsplit_once('/').unwrap_or(("", pattern));
    let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
    pattern_dir == dir && name_match(pattern_name, name)
}

/// Tells if a file is data: not a `LICENSE` file, not Markdown and not a dot file.
fn is_data(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name != "LICENSE" && !name.starts_with('.') && !has_extension(name, "md")
}

/// Tells if a path is an embedded data file of a crate (`crates/*/data/`).
fn is_embedded(path: &str) -> bool {
    let mut parts = path.split('/');
    parts.next() == Some("crates") && parts.nth(1) == Some("data")
}

/// Gives the directories of `path` that hold a `LICENSE` file of `licensed`.
fn licensed_dir<'a>(path: &str, licensed: &'a BTreeSet<String>) -> Option<&'a str> {
    licensed
        .iter()
        .find(|dir| {
            path.strip_prefix(dir.as_str())
                .is_some_and(|r| r.starts_with('/'))
        })
        .map(String::as_str)
}

/// Tells if a header names a copyright holder other than ghidorah.
fn foreign_copyright(head: &str) -> bool {
    head.lines()
        .any(|l| l.contains("Copyright") && !l.contains("ghidorah"))
}

/// Tells if a header names a source and a license.
fn names_source_and_license(head: &str) -> bool {
    head.contains("Source") && (head.contains("License") || head.contains("license"))
}

/// Makes one AC-027 finding.
fn finding(path: &str, line: usize, detail: impl Into<String>) -> Finding {
    Finding::new("AC-027", path, line, detail)
}

/// Checks each ledger row: its columns, its data file and its `NOTICE` entry.
fn check_rows(rows: &[LedgerRow], notice: &str, files: &[DataFile], found: &mut Vec<Finding>) {
    for row in rows {
        if row.source.is_empty() || row.license.is_empty() {
            found.push(finding(LEDGER, row.line, "name the source and the license"));
        }
        if !files.iter().any(|f| glob_match(&row.pattern, &f.path)) {
            let detail = format!("`{}` matches no data file", row.pattern);
            found.push(finding(LEDGER, row.line, detail));
        }
        if !notice.contains(&row.pattern) {
            found.push(finding(NOTICE, 0, format!("list `{}`", row.pattern)));
        }
    }
}

/// Checks that each data entry `- <path>: ..` of `NOTICE` has a ledger row.
fn check_notice(rows: &[LedgerRow], notice: &str, found: &mut Vec<Finding>) {
    for (index, line) in notice.lines().enumerate() {
        let Some((path, _)) = line.strip_prefix("- ").and_then(|l| l.split_once(": ")) else {
            continue;
        };
        if !rows.iter().any(|r| r.pattern == path) {
            let detail = format!("`{path}` has no ledger row");
            found.push(finding(NOTICE, index + 1, detail));
        }
    }
}

/// Checks that each vendored file has a ledger row. Each file of a row and each embedded
/// file must name its source and its license.
fn check_files(rows: &[LedgerRow], files: &[DataFile], found: &mut Vec<Finding>) {
    let by_path: BTreeMap<&str, &DataFile> = files.iter().map(|f| (f.path.as_str(), f)).collect();
    let licensed: BTreeSet<String> = files
        .iter()
        .filter_map(|f| f.path.strip_suffix("/LICENSE"))
        .map(str::to_owned)
        .collect();
    for file in files.iter().filter(|f| is_data(&f.path)) {
        let dir = licensed_dir(&file.path, &licensed);
        let head = file.head.as_deref();
        let vendored = dir.is_some() || head.is_some_and(foreign_copyright);
        let listed = rows.iter().any(|r| glob_match(&r.pattern, &file.path));
        if vendored && !listed {
            found.push(finding(
                &file.path,
                0,
                "add the vendored file to the ledger",
            ));
        }
        if !(listed || is_embedded(&file.path)) {
            continue;
        }
        let readme = dir.map(|d| format!("{d}/README.md"));
        let header = match (head, has_extension(&file.path, "json")) {
            (Some(text), false) => Some(text),
            _ => readme
                .as_deref()
                .and_then(|r| by_path.get(r))
                .and_then(|f| f.head.as_deref()),
        };
        match header {
            Some(text) if names_source_and_license(text) => {}
            Some(_) => found.push(finding(&file.path, 1, "name the source and the license")),
            None if listed => found.push(finding(&file.path, 0, "add a README.md with the source")),
            None => {}
        }
    }
}

/// AC-027: checks the ledger, the notice and the data files.
#[must_use]
pub fn license_ledger(notice: &str, ledger: &str, files: &[DataFile]) -> Vec<Finding> {
    let rows = ledger_rows(ledger);
    let mut found = Vec::new();
    check_rows(&rows, notice, files, &mut found);
    check_notice(&rows, notice, &mut found);
    check_files(&rows, files, &mut found);
    found
}

/// Adds each file under `dir` (relative to `root`) to `out`.
fn walk(root: &Path, dir: &str, depth: usize, out: &mut Vec<DataFile>) -> Result<(), Error> {
    let full = root.join(dir);
    let Ok(entries) = std::fs::read_dir(&full) else {
        return Ok(());
    };
    for entry in entries {
        if depth > MAX_DEPTH || out.len() >= MAX_FILES {
            break;
        }
        let entry = entry.map_err(|e| Error::io(&full, e))?;
        let rel = format!("{dir}/{}", entry.file_name().to_string_lossy());
        let kind = entry.file_type().map_err(|e| Error::io(&full, e))?;
        if kind.is_dir() {
            walk(root, &rel, depth + 1, out)?;
        } else if kind.is_file() {
            let bytes = std::fs::read(entry.path()).map_err(|e| Error::io(entry.path(), e))?;
            let head = String::from_utf8(bytes).ok().map(|text| {
                text.lines()
                    .take(HEADER_LINES)
                    .collect::<Vec<_>>()
                    .join("\n")
            });
            out.push(DataFile { path: rel, head });
        }
    }
    Ok(())
}

/// Gives the data files of the repository in path order.
///
/// # Errors
///
/// Returns [`Error::Io`] when a directory or a file does not read.
pub fn data_files(root: &Path) -> Result<Vec<DataFile>, Error> {
    let mut out = Vec::new();
    walk(root, "tests/data", 0, &mut out)?;
    let crates = root.join("crates");
    let entries = std::fs::read_dir(&crates).map_err(|e| Error::io(&crates, e))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(&crates, e))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    for name in names {
        walk(root, &format!("crates/{name}/data"), 0, &mut out)?;
        walk(root, &format!("crates/{name}/tests/data"), 0, &mut out)?;
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// The AC-027 gate over the repository at `root`.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file does not read.
pub fn check_ledger(root: &Path) -> Result<Vec<Finding>, Error> {
    Ok(license_ledger(
        &read(root, NOTICE)?,
        &read(root, LEDGER)?,
        &data_files(root)?,
    ))
}
