//! The doc gates of WP-28 (design Section 15.3): AC-023a and AC-023b.
//!
//! | Gate | Check |
//! |---|---|
//! | AC-023a | The files of [`REQUIRED`] exist. Each relative link of [`README`] names a path. The ADR index lists each ADR file once, with its status. |
//! | AC-023b | Each ADR has `## Alternatives` and `Verified by:`, and that line names MVP ACs only. |
//!
//! The module [`super::ledger`] holds the AC-027 gate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::{Error, Finding};

/// The doc files that must exist (AC-023a).
pub const REQUIRED: [&str; 6] = [
    "README.md",
    "CLAUDE.md",
    "docs/design.md",
    "docs/adr/README.md",
    "docs/GLOSSARY.md",
    "docs/errors.md",
];

/// The top-level README.
pub const README: &str = "README.md";

/// The ADR directory.
pub const ADR_DIR: &str = "docs/adr";

/// The ADR index.
pub const ADR_INDEX: &str = "docs/adr/README.md";

/// One row of the ADR index table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRow {
    /// The number in the link text, for example `0001`.
    pub number: String,
    /// The file name of the link, for example `0001-zero-third-party-dependencies.md`.
    pub file: String,
    /// The text of the status column.
    pub status: String,
    /// The 1-based line in the index.
    pub line: usize,
}

/// Tells if the path `path` has the extension `ext`, in any letter case.
pub(crate) fn has_extension(path: &str, ext: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// Tells if `name` is the file name of an ADR: four digits, a dash and `.md`.
#[must_use]
pub fn is_adr_file(name: &str) -> bool {
    let digits = name.chars().take_while(char::is_ascii_digit).count();
    digits == 4 && name.get(4..5) == Some("-") && name.len() > 8 && has_extension(name, "md")
}

/// Gives the cells of a Markdown table line, without the outer bars.
pub(crate) fn cells(line: &str) -> Vec<&str> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    inner.split('|').map(str::trim).collect()
}

/// Gives the text of the first code span of `cell`.
pub(crate) fn first_code(cell: &str) -> Option<&str> {
    cell.split('`').nth(1).filter(|s| !s.is_empty())
}

/// Gives the `[text](target)` links of a Markdown text with their 1-based lines.
fn links(text: &str) -> Vec<(usize, &str, &str)> {
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(open) = rest.find('[') {
            let after = rest.get(open + 1..).unwrap_or_default();
            let Some(close) = after.find("](") else {
                break;
            };
            let label = after.get(..close).unwrap_or_default();
            let tail = after.get(close + 2..).unwrap_or_default();
            let Some(end) = tail.find(')') else {
                break;
            };
            out.push((index + 1, label, tail.get(..end).unwrap_or_default()));
            rest = tail.get(end + 1..).unwrap_or_default();
        }
    }
    out
}

/// Gives the rows of the ADR index table.
#[must_use]
pub fn index_rows(index: &str) -> Vec<IndexRow> {
    let mut rows = Vec::new();
    for (i, line) in index.lines().enumerate() {
        if !line.starts_with("| [") {
            continue;
        }
        let parts = cells(line);
        let (Some(link), Some(status)) = (parts.first(), parts.get(2)) else {
            continue;
        };
        let Some((_, number, file)) = links(link).into_iter().next() else {
            continue;
        };
        rows.push(IndexRow {
            number: number.to_owned(),
            file: file.to_owned(),
            status: (*status).to_owned(),
            line: i + 1,
        });
    }
    rows
}

/// AC-023a: gives one finding for each file of [`REQUIRED`] that `exists` does not find.
#[must_use]
pub fn missing_docs(exists: &dyn Fn(&str) -> bool) -> Vec<Finding> {
    REQUIRED
        .iter()
        .filter(|p| !exists(p))
        .map(|p| Finding::new("AC-023a", *p, 0, "add the file"))
        .collect()
}

/// AC-023a: gives one finding for each relative link of `readme` whose path `exists` does not
/// find. The check skips a link with a scheme and a link to an anchor only.
#[must_use]
pub fn readme_links(readme: &str, exists: &dyn Fn(&str) -> bool) -> Vec<Finding> {
    let mut found = Vec::new();
    for (line, _, target) in links(readme) {
        let path = target.split('#').next().unwrap_or_default();
        if path.is_empty() || target.contains("://") || target.starts_with("mailto:") {
            continue;
        }
        if !exists(path) {
            found.push(Finding::new(
                "AC-023a",
                README,
                line,
                format!("the link `{target}` names no file"),
            ));
        }
    }
    found
}

/// Gives the value of the `Status:` line of an ADR.
fn status_of(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|l| l.strip_prefix("Status:"))
        .map(str::trim)
}

/// Gives the first word of a status, for example `Accepted`.
fn status_word(status: &str) -> &str {
    status
        .split(|c: char| !c.is_ascii_alphabetic())
        .next()
        .unwrap_or_default()
}

/// Checks one ADR file against its index row.
fn index_entry(name: &str, text: &str, row: &IndexRow, found: &mut Vec<Finding>) {
    let rel = format!("{ADR_DIR}/{name}");
    let mut push = |line: usize, detail: String| {
        found.push(Finding::new("AC-023a", rel.as_str(), line, detail));
    };
    let number = name.get(..4).unwrap_or_default();
    if row.number != number {
        push(0, format!("the index row names `{}`", row.number));
    }
    let title = format!("# ADR-{number}:");
    if !text.lines().next().is_some_and(|l| l.starts_with(&title)) {
        push(1, format!("start the file with `{title}`"));
    }
    let Some(status) = status_of(text) else {
        push(0, "add a `Status:` line".to_owned());
        return;
    };
    if status_word(status) != status_word(&row.status) {
        push(0, format!("the index status `{}` differs", row.status));
    }
    let amended = text.lines().any(|l| l.starts_with("## Amendment"));
    if status.contains("amended") != amended {
        push(
            0,
            "the `Status:` line and the amendment sections differ".to_owned(),
        );
    }
    if row.status.contains("amended") != amended {
        push(0, format!("the index status `{}` differs", row.status));
    }
}

/// AC-023a: compares the ADR index with the ADR files, given as `(file name, text)` pairs.
///
/// Each file needs one index row with its number, a `Status:` line and an `# ADR-NNNN:` title.
/// The first word of the two statuses must agree. The word `amended` must be in both
/// statuses exactly when the file has an `## Amendment` section.
#[must_use]
pub fn adr_index(index: &str, adrs: &[(String, String)]) -> Vec<Finding> {
    let rows = index_rows(index);
    let mut found = Vec::new();
    let mut by_file: BTreeMap<&str, Vec<&IndexRow>> = BTreeMap::new();
    for row in &rows {
        by_file.entry(row.file.as_str()).or_default().push(row);
    }
    let names: BTreeSet<&str> = adrs.iter().map(|(n, _)| n.as_str()).collect();
    for row in &rows {
        if !names.contains(row.file.as_str()) {
            found.push(Finding::new(
                "AC-023a",
                ADR_INDEX,
                row.line,
                format!("the row names `{}`, which does not exist", row.file),
            ));
        }
    }
    for (name, text) in adrs {
        match by_file.get(name.as_str()).map(Vec::as_slice) {
            Some([row]) => index_entry(name, text, row, &mut found),
            Some(_) => found.push(Finding::new(
                "AC-023a",
                ADR_INDEX,
                0,
                format!("list `{name}` once"),
            )),
            None => found.push(Finding::new(
                "AC-023a",
                ADR_INDEX,
                0,
                format!("add a row for `{name}`"),
            )),
        }
    }
    found
}

/// Gives the AC IDs of a text, for example `AC-001a`.
fn ac_ids(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (at, _) in text.match_indices("AC-") {
        let rest = text.get(at + 3..).unwrap_or_default();
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.len() != 3 {
            continue;
        }
        let letter = rest
            .chars()
            .nth(3)
            .filter(char::is_ascii_lowercase)
            .map(String::from)
            .unwrap_or_default();
        out.push(format!("AC-{digits}{letter}"));
    }
    out
}

/// Tells if the AC ID `id` names a row of `acs`. An ID without a letter also names the
/// lettered rows of its number.
fn names_row(id: &str, acs: &BTreeSet<String>) -> bool {
    acs.contains(id)
        || (id.len() == 6
            && acs
                .range(id.to_owned()..)
                .next()
                .is_some_and(|a| a.starts_with(id)))
}

/// AC-023b: checks the sections of one ADR. `acs` holds the IDs of the MVP AC rows.
///
/// An ID without a letter also names the lettered rows of its number, for example `AC-175`
/// names `AC-175a`.
#[must_use]
pub fn adr_sections(rel: &str, text: &str, acs: &BTreeSet<String>) -> Vec<Finding> {
    let mut found = Vec::new();
    if !text.lines().any(|l| l.trim_end() == "## Alternatives") {
        found.push(Finding::new(
            "AC-023b",
            rel,
            0,
            "add an `## Alternatives` section",
        ));
    }
    let verified = text
        .lines()
        .enumerate()
        .find(|(_, l)| l.starts_with("Verified by:"));
    let Some((index, line)) = verified else {
        found.push(Finding::new("AC-023b", rel, 0, "add a `Verified by:` line"));
        return found;
    };
    for id in ac_ids(line) {
        if !names_row(&id, acs) {
            found.push(Finding::new(
                "AC-023b",
                rel,
                index + 1,
                format!("`{id}` is not an MVP AC of the design"),
            ));
        }
    }
    found
}

/// Reads the text of a file relative to `root`.
pub(crate) fn read(root: &Path, rel: &str) -> Result<String, Error> {
    let path = root.join(rel);
    std::fs::read_to_string(&path).map_err(|e| Error::io(path, e))
}

/// Gives the ADR files of the repository as `(file name, text)` pairs in name order.
///
/// # Errors
///
/// Returns [`Error::Io`] when the directory or a file does not read.
pub fn adr_files(root: &Path) -> Result<Vec<(String, String)>, Error> {
    let dir = root.join(ADR_DIR);
    let entries = std::fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(&dir, e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_adr_file(&name) {
            let text = read(root, &format!("{ADR_DIR}/{name}"))?;
            out.push((name, text));
        }
    }
    out.sort();
    Ok(out)
}

/// The AC-023a gate over the repository at `root`.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file does not read.
pub fn check_present(root: &Path) -> Result<Vec<Finding>, Error> {
    let exists = |rel: &str| root.join(rel).exists();
    let mut found = missing_docs(&exists);
    if exists(README) {
        found.extend(readme_links(&read(root, README)?, &exists));
    }
    if exists(ADR_INDEX) {
        found.extend(adr_index(&read(root, ADR_INDEX)?, &adr_files(root)?));
    }
    Ok(found)
}

/// The AC-023b gate over the repository at `root`.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file does not read.
pub fn check_adrs(root: &Path) -> Result<Vec<Finding>, Error> {
    let (rows, _) = crate::ac::parse_rows(&read(root, crate::ac::DESIGN_PATH)?);
    let acs: BTreeSet<String> = rows
        .into_iter()
        .filter(crate::ac::AcRow::is_gate)
        .map(|r| r.id)
        .collect();
    let mut found = Vec::new();
    for (name, text) in adr_files(root)? {
        found.extend(adr_sections(&format!("{ADR_DIR}/{name}"), &text, &acs));
    }
    Ok(found)
}
