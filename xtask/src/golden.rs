//! The `xtask golden` command: bless goldens and check their headers (design Section 13.7).
//!
//! | Command | Effect |
//! |---|---|
//! | `xtask golden bless [cargo test args]` | Runs `cargo test --workspace` with `GHIDORAH_BLESS=1`. Prints the count of changed golden files per area. |
//! | `xtask golden headers` | Checks the golden headers against `fixtures/manifest.json` (AC-022). |
//!
//! An area is the first directory under `tests/golden`, for example `loader`. A file at the top
//! of `tests/golden` has the area `.`. The command sets the bless variable only for its child
//! `cargo` process (ADR-0012).

use std::collections::BTreeMap;
use std::path::Path;

use crate::Error;
use crate::json::Value;

/// The golden root, relative to the workspace root.
pub const ROOT: &str = "tests/golden";

/// The hash of each golden file, keyed by its path relative to the workspace root.
pub type Snapshot = BTreeMap<String, [u8; 32]>;

/// Gives the hash of each golden file of the workspace.
///
/// # Errors
///
/// Returns [`Error::Io`] when a file or a directory does not read.
pub fn snapshot(root: &Path) -> Result<Snapshot, Error> {
    let _ = root;
    Ok(Snapshot::new())
}

/// Gives the area of a golden path: `tests/golden/loader/x.txt` gives `loader`.
#[must_use]
pub fn area(path: &str) -> &str {
    path.get(..0).unwrap_or_default()
}

/// Gives the count of added, removed and changed files per area between two snapshots.
#[must_use]
pub fn changes(before: &Snapshot, after: &Snapshot) -> BTreeMap<String, u64> {
    let _ = (before, after);
    BTreeMap::new()
}

/// Runs `xtask golden <bless|headers>`.
///
/// # Errors
///
/// Returns [`Error::Usage`] for an unknown command, or the error of the command.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let _ = (root, args);
    Err(Error::Usage(
        "cargo xtask golden <bless|headers>".to_owned(),
    ))
}
