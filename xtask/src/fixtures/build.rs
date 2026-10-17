//! `xtask fixtures build`: the fixture binaries, the goldens, the truth files and the manifest.
//!
//! The build works in `target/fixtures-work`. For each program and build it copies the
//! sources into one directory, compiles each source with `-c` and links with
//! `-Wl,-Map`. Then it makes the variants, runs the fact runs, writes the goldens, runs the
//! leaf driver and assembles the truth file. With `--check`, it writes into
//! `target/fixtures-check` and compares each file with the checked-in file.

use std::path::Path;

use crate::Error;
use crate::json::Value;

/// The work directory, relative to the workspace root.
pub const WORK_DIR: &str = "target/fixtures-work";

/// The output root of `--check`, relative to the workspace root.
pub const CHECK_DIR: &str = "target/fixtures-check";

/// Runs the build. With `check`, it compares the outputs with the checked-in files.
///
/// Output: `{ ok, fixtures, total_bytes, differences }`.
///
/// # Errors
///
/// Returns an error when a tool is missing, a build step fails or a fact does not hold.
pub fn run(root: &Path, check: bool) -> Result<Value, Error> {
    let _ = (root, check);
    Err(Error::data(WORK_DIR, "no fixture build yet"))
}
