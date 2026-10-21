//! Shared helpers: fixture paths, golden files and load calls.

use std::path::PathBuf;

use ghidorah_base::{DiagCode, Limits};
use ghidorah_loader::{Binary, LoadError, LoadOpts, MemoryMap, load};
use ghidorah_testkit::golden::{self, Header};

/// The workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The names of the checked-in ELF fixtures, sorted.
pub fn fixture_names() -> Vec<String> {
    let dir = root().join("fixtures/bin");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The bytes of a fixture.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = root().join("fixtures/bin").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The header and the body of `tests/golden/loader/<file>`.
pub fn golden(file: &str) -> (Header, String) {
    let path = root().join("tests/golden/loader").join(file);
    golden::read(&path).unwrap_or_else(|e| panic!("golden {}: {e}", path.display()))
}

/// Tells if `tests/golden/loader/<file>` exists.
pub fn has_golden(file: &str) -> bool {
    root().join("tests/golden/loader").join(file).is_file()
}

/// Loads `bytes` with the default settings and limits.
pub fn try_load(bytes: &[u8]) -> Result<(Binary, MemoryMap), LoadError> {
    load(bytes, &LoadOpts::AUTO, &Limits::DEFAULT)
}

/// Loads `bytes` and fails the test on an error.
pub fn load_ok(bytes: &[u8]) -> (Binary, MemoryMap) {
    try_load(bytes).unwrap_or_else(|e| panic!("load fails: {e}"))
}

/// Gives the diagnostic codes of a load: the kept list, or the code of the error.
pub fn codes_of(bytes: &[u8]) -> Vec<DiagCode> {
    match try_load(bytes) {
        Ok((binary, _)) => binary.diagnostics.iter().map(|d| d.code).collect(),
        Err(LoadError::Malformed(diag)) => vec![diag.code],
        Err(other) => panic!("unexpected load error: {other}"),
    }
}
