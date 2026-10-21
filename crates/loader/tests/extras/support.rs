//! Shared helpers: fixture paths, golden files and load calls.

use std::path::PathBuf;

use ghidorah_base::{DiagCode, Limits};
use ghidorah_loader::{Binary, LoadOpts, MemoryMap, load};
use ghidorah_testkit::golden;

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

/// Tells if `fixtures/bin/<name>` exists.
pub fn has_fixture(name: &str) -> bool {
    root().join("fixtures/bin").join(name).is_file()
}

/// The body of `tests/golden/<area>/<file>`, or `None` when the file does not exist.
pub fn golden_body(area: &str, file: &str) -> Option<String> {
    let path = root().join("tests/golden").join(area).join(file);
    if !path.is_file() {
        return None;
    }
    let (_, body) =
        golden::read(&path).unwrap_or_else(|e| panic!("golden {}: {e}", path.display()));
    Some(body)
}

/// Loads `bytes` with the default settings and limits, and fails the test on an error.
pub fn load_ok(bytes: &[u8]) -> (Binary, MemoryMap) {
    load(bytes, &LoadOpts::AUTO, &Limits::DEFAULT).unwrap_or_else(|e| panic!("load fails: {e}"))
}

/// Gives the diagnostic codes of a loaded file.
pub fn codes(binary: &Binary) -> Vec<DiagCode> {
    binary.diagnostics.iter().map(|d| d.code).collect()
}

/// Gives the name of an import as text.
pub fn import_name(binary: &Binary, index: usize) -> String {
    binary.imports[index]
        .name
        .as_ref()
        .map(|n| String::from_utf8_lossy(n.as_bytes()).into_owned())
        .unwrap_or_default()
}

/// Parses a hex number without the `0x` prefix.
pub fn hex(text: &str) -> u64 {
    u64::from_str_radix(text.trim(), 16).unwrap_or_else(|e| panic!("hex {text:?}: {e}"))
}
