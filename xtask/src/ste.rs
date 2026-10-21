//! The `xtask ste` command: the ASD-STE100 check of docs and comments (ADR-0019, AC-025).
//!
//! The command is a wrapper over `ghidorah_testkit::ste`. It reads every Markdown file and the
//! comments of every Rust file of the repository, except `docs/research.md` and `docs/planning/`.
//! It uses warn mode, so the reviewed entries of `docs/ste-allowlist.txt` apply.
//!
//! Output: `{ ok, files, allowed, findings, allow, unused }`.
//!
//! - `findings` holds one [`Finding`] for each finding that no allowlist entry allows.
//! - `allow` holds the allowlist line for each finding, in the same order.
//!   Add a line to the allowlist only after a review of the sentence.
//! - `unused` holds the allowlist entries that allow no finding. They do not make `ok` false.

use std::path::Path;

use ghidorah_testkit::ste::{self, AllowEntry, Checker, Mode, ScanReport};

use crate::json::Value;
use crate::{Error, Finding};

/// Gives the gate finding of one STE finding.
#[must_use]
pub fn finding(found: &ste::FileFinding) -> Finding {
    let inner = &found.finding;
    Finding::new(
        inner.rule.id(),
        found.path.as_str(),
        inner.line,
        format!("{}: {}", inner.detail, inner.sentence),
    )
}

/// Gives the JSON report of a scan.
#[must_use]
pub fn report(scan: &ScanReport) -> Value {
    let findings: Vec<Value> = scan.findings.iter().map(|f| finding(f).to_json()).collect();
    let allow: Vec<Value> = scan
        .findings
        .iter()
        .map(|f| Value::from(AllowEntry::for_finding(&f.path, &f.finding).to_string()))
        .collect();
    let unused: Vec<Value> = scan
        .unused
        .iter()
        .map(|e| Value::from(e.to_string()))
        .collect();
    Value::object([
        ("ok", Value::from(scan.ok())),
        ("files", Value::from(scan.files)),
        ("allowed", Value::from(scan.allowed)),
        ("findings", Value::from(findings)),
        ("allow", Value::from(allow)),
        ("unused", Value::from(unused)),
    ])
}

/// Runs `xtask ste` over the repository at `root`.
///
/// # Errors
///
/// Returns [`Error::Usage`] for an argument, [`Error::Data`] when the allowlist does not parse
/// and [`Error::Io`] when a file or directory does not read.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    if !args.is_empty() {
        return Err(Error::Usage("cargo xtask ste".to_owned()));
    }
    let allowlist =
        ste::repo_allowlist(root).map_err(|e| Error::data(ste::ALLOWLIST_PATH, e.to_string()))?;
    let checker = Checker::new(ste::repo_lexicon(root));
    let scan =
        ste::scan_repo(root, &checker, Mode::Warn, &allowlist).map_err(|e| Error::io(root, e))?;
    Ok(report(&scan))
}
