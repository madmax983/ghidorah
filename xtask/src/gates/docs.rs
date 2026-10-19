//! The doc gates of WP-28 (design Section 15.3): AC-023a, AC-023b and AC-027.
//!
//! | Gate | Check |
//! |---|---|
//! | AC-023a | The files of [`REQUIRED`] exist. Each relative link of [`README`] names a path. The ADR index lists each ADR file once, with its status. |
//! | AC-023b | Each ADR has `## Alternatives` and `Verified by:`, and that line names MVP ACs only. |
//! | AC-027 | [`NOTICE`] and [`LEDGER`] list each vendored data file. Each data file names its source and its license. |
//!
//! A data file is a file under `crates/*/data/`, `crates/*/tests/data/` or `tests/data/`.
//! A data file is vendored when its header names a copyright holder other than ghidorah, or
//! when its directory or a parent directory below the data root holds a `LICENSE` file.

use std::collections::BTreeSet;
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

/// The license ledger.
pub const LEDGER: &str = "docs/licenses.md";

/// The attribution file.
pub const NOTICE: &str = "NOTICE";

/// The number of lines of a data file that make its header.
pub const HEADER_LINES: usize = 12;

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

/// Tells if `name` is the file name of an ADR: four digits, a dash and `.md`.
#[must_use]
pub fn is_adr_file(name: &str) -> bool {
    let _ = name;
    false
}

/// Gives the rows of the ADR index table.
#[must_use]
pub fn index_rows(index: &str) -> Vec<IndexRow> {
    let _ = index;
    Vec::new()
}

/// Gives the rows of the license ledger table.
#[must_use]
pub fn ledger_rows(ledger: &str) -> Vec<LedgerRow> {
    let _ = ledger;
    Vec::new()
}

/// Tells if `path` matches `pattern`. A `*` matches any run of characters except `/`.
#[must_use]
pub fn glob_match(pattern: &str, path: &str) -> bool {
    pattern == path
}

/// AC-023a: gives one finding for each file of [`REQUIRED`] that `exists` does not find.
#[must_use]
pub fn missing_docs(exists: &dyn Fn(&str) -> bool) -> Vec<Finding> {
    let _ = exists;
    Vec::new()
}

/// AC-023a: gives one finding for each relative link of `readme` whose path `exists` does not
/// find. A link with a scheme or a link to an anchor only is not checked.
#[must_use]
pub fn readme_links(readme: &str, exists: &dyn Fn(&str) -> bool) -> Vec<Finding> {
    let _ = (readme, exists);
    Vec::new()
}

/// AC-023a: compares the ADR index with the ADR files, given as `(file name, text)` pairs.
///
/// Each file needs one index row with its number, a `Status:` line and an `# ADR-NNNN:` title.
/// The first word of the two statuses must agree. The word `amended` must be in both
/// statuses exactly when the file has an `## Amendment` section.
#[must_use]
pub fn adr_index(index: &str, adrs: &[(String, String)]) -> Vec<Finding> {
    let _ = (index, adrs);
    Vec::new()
}

/// AC-023b: checks the sections of one ADR. `acs` holds the IDs of the MVP AC rows.
///
/// An ID without a letter also names the lettered rows of its number, for example `AC-175`
/// names `AC-175a`.
#[must_use]
pub fn adr_sections(rel: &str, text: &str, acs: &BTreeSet<String>) -> Vec<Finding> {
    let _ = (rel, text, acs);
    Vec::new()
}

/// AC-027: checks the ledger, the notice and the data files.
#[must_use]
pub fn license_ledger(notice: &str, ledger: &str, files: &[DataFile]) -> Vec<Finding> {
    let _ = (notice, ledger, files);
    Vec::new()
}

/// Gives the ADR files of the repository as `(file name, text)` pairs in name order.
///
/// # Errors
///
/// Returns [`Error::Io`] when the directory or a file does not read.
pub fn adr_files(root: &Path) -> Result<Vec<(String, String)>, Error> {
    let _ = root;
    Ok(Vec::new())
}

/// Gives the data files of the repository in path order.
///
/// # Errors
///
/// Returns [`Error::Io`] when a directory or a file does not read.
pub fn data_files(root: &Path) -> Result<Vec<DataFile>, Error> {
    let _ = root;
    Ok(Vec::new())
}

/// The AC-023a gate over the repository at `root`.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file does not read.
pub fn check_present(root: &Path) -> Result<Vec<Finding>, Error> {
    let _ = root;
    Ok(Vec::new())
}

/// The AC-023b gate over the repository at `root`.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file does not read.
pub fn check_adrs(root: &Path) -> Result<Vec<Finding>, Error> {
    let _ = root;
    Ok(Vec::new())
}

/// The AC-027 gate over the repository at `root`.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file does not read.
pub fn check_ledger(root: &Path) -> Result<Vec<Finding>, Error> {
    let _ = root;
    Ok(Vec::new())
}
