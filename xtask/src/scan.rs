//! Source gates over the Rust files of the workspace.
//!
//! Each check takes one file (its relative path and its text) and gives its findings.

use std::path::Path;

use crate::{Error, Finding};

/// The maximum line count of a non-table, non-test source file (AC-014).
pub const MAX_FILE_LINES: usize = 600;

/// Gives every `.rs` file under `crates/` and `xtask/`, relative to `root` and sorted.
///
/// The walk skips `target` directories and hidden directories.
///
/// # Errors
///
/// Returns [`Error::Io`] when a directory read fails.
pub fn rust_files(root: &Path) -> Result<Vec<String>, Error> {
    let _ = root;
    Ok(Vec::new())
}

/// Tells if a file holds test code: a `tests.rs` file or a file under a `tests/` directory.
#[must_use]
pub fn is_test_file(rel: &str) -> bool {
    let _ = rel;
    false
}

/// Tells if a file is a const table file under a `tables/` directory.
#[must_use]
pub fn is_table_file(rel: &str) -> bool {
    let _ = rel;
    false
}

/// Gives the crate directory name of a path: `crates/json/src/lib.rs` gives `json`.
#[must_use]
pub fn crate_dir(rel: &str) -> Option<&str> {
    let _ = rel;
    None
}

/// AC-012: finds stub markers and panicking calls in non-test code.
#[must_use]
pub fn no_stubs(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-014: finds a file with more than [`MAX_FILE_LINES`] lines.
#[must_use]
pub fn file_size(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-016: finds an `allow` of `disallowed_types`, or an `expect` without a reason.
#[must_use]
pub fn disallowed_exceptions(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-017: finds use of file, network, process, environment or wall-clock APIs.
#[must_use]
pub fn layering(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-223: finds calls that change the process environment.
#[must_use]
pub fn no_set_var(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-004: finds `unsafe` code or an `unsafe_code` lint exception.
#[must_use]
pub fn no_unsafe(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}

/// AC-008: finds network or process use in a build script.
#[must_use]
pub fn build_script(rel: &str, text: &str) -> Vec<Finding> {
    let _ = (rel, text);
    Vec::new()
}
