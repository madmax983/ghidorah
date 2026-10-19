//! Shared helpers: the PE fixtures, their goldens and truth files, and load calls.

use std::path::PathBuf;

use ghidorah_base::{DiagCode, Limits};
use ghidorah_loader::{Binary, LoadError, LoadOpts, MemoryMap, load};
use ghidorah_testkit::golden;
use ghidorah_testkit::pe;

use crate::readobj::{self, Node};

/// The PE fixture images.
pub const IMAGES: [&str; 4] = ["pe_cc.exe", "pe_dll.dll", "pe_flags.exe", "pe_main.exe"];

/// The workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The bytes of the PE fixture `name`.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = root().join("fixtures/bin/pe").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `llvm-readobj` golden of `name`, parsed.
pub fn readobj(name: &str) -> Node {
    let path = root()
        .join("tests/golden/loader/pe")
        .join(format!("{name}.readobj.txt"));
    let (_, body) =
        golden::read(&path).unwrap_or_else(|e| panic!("golden {}: {e}", path.display()));
    readobj::parse(&body)
}

/// The truth file text of the image `name`.
pub fn truth(name: &str) -> String {
    let program = name.split('.').next().unwrap_or(name);
    let path = root()
        .join("fixtures/truth/pe")
        .join(format!("{program}.json"));
    std::fs::read_to_string(&path).expect("the truth file")
}

/// Gives the value text of the first member `key` of a pretty truth file, without quotes.
///
/// The truth files have one member on each line, so a line scan finds a key with one use.
pub fn truth_field(text: &str, key: &str) -> String {
    let marker = format!("\"{key}\": ");
    text.lines()
        .find_map(|l| l.trim().strip_prefix(marker.as_str()))
        .map_or_else(
            || panic!("no member {key}"),
            |v| v.trim_end_matches(',').trim_matches('"').to_owned(),
        )
}

/// Loads `bytes` with the default settings and limits.
pub fn try_load(bytes: &[u8]) -> Result<(Binary, MemoryMap), LoadError> {
    load(bytes, &LoadOpts::AUTO, &Limits::DEFAULT)
}

/// Loads `bytes` and fails the test on an error.
pub fn load_ok(bytes: &[u8]) -> (Binary, MemoryMap) {
    try_load(bytes).unwrap_or_else(|e| panic!("load fails: {e}"))
}

/// Loads the PE fixture `name`.
pub fn load_fixture(name: &str) -> (Binary, MemoryMap) {
    load_ok(&fixture(name))
}

/// Loads the `PeBuilder` variant `name`.
pub fn load_variant(name: &str) -> (Binary, MemoryMap) {
    let b = pe::builder(name).unwrap_or_else(|| panic!("no variant {name}"));
    load_ok(&b.build())
}

/// Gives the diagnostic codes of a model.
pub fn codes(binary: &Binary) -> Vec<DiagCode> {
    binary.diagnostics.iter().map(|d| d.code).collect()
}

/// Reads `len` bytes at `va` of a map.
pub fn read(map: &MemoryMap, va: u64, len: u64) -> Vec<u8> {
    map.read(va, len, &Limits::DEFAULT)
        .unwrap_or_else(|e| panic!("read {va:#x}: {e}"))
        .into_owned()
}

/// Gives the text of a binary text, or an empty text.
pub fn text(t: Option<&ghidorah_base::BinText>) -> String {
    t.and_then(|t| t.as_str()).unwrap_or_default().to_owned()
}
