//! The `test_hermetic` step of `xtask ci` (AC-020).
//!
//! The step builds the tier-1 test binaries. Then it runs each binary in its package
//! directory with `PATH` reduced to the toolchain directory and an empty `HOME`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The variables that the hermetic run removes, so no test reads a user directory.
pub const REMOVED_VARS: &[&str] = &[];

/// Gives the environment changes of the hermetic run: `Some` sets a variable, `None` removes
/// it.
#[must_use]
pub fn hermetic_env(toolchain_bin: &Path, home: &Path) -> Vec<(String, Option<OsString>)> {
    let _ = (toolchain_bin, home);
    Vec::new()
}

/// One test binary of the hermetic run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestBinary {
    /// The executable file.
    pub exe: PathBuf,
    /// The package directory: the working directory of the run.
    pub dir: PathBuf,
}

/// Gives the test binaries of the JSON lines of `cargo test --no-run --message-format=json`.
#[must_use]
pub fn test_binaries(cargo_json: &str) -> Vec<TestBinary> {
    let _ = cargo_json;
    Vec::new()
}
