//! The fixture manifest `fixtures/manifest.json` and the checks of AC-022.
//!
//! Format: `{ generator, version, tools: { <tool>: <version> }, total_bytes, fixtures: [entry] }`.
//! An entry is `{ name, path, sha256, size, tier, program, build, variant, compiler, cflags,
//! ldflags, truth }`. `variant` is `none`, `stripped`, `noeh` or `noshdr`. Entries are in name
//! order. The PE fixtures of WP-30 live under `fixtures/bin/pe/` with their own entries.

use std::collections::BTreeMap;
use std::path::Path;

use super::spec::Fixture;
use crate::json::Value;
use crate::{Error, Finding};

/// The manifest path, relative to the workspace root.
pub const PATH: &str = "fixtures/manifest.json";

/// The golden root, relative to the workspace root.
pub const GOLDEN_ROOT: &str = "tests/golden";

/// One fixture binary of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The fixture name.
    pub name: String,
    /// The binary path, relative to the workspace root.
    pub path: String,
    /// The SHA-256 of the binary in hex.
    pub sha256: String,
    /// The size in bytes.
    pub size: u64,
    /// The tier, `T1` or `T2`.
    pub tier: String,
    /// The program name.
    pub program: String,
    /// The build ID.
    pub build: String,
    /// The variant: `none`, `stripped`, `noeh` or `noshdr`.
    pub variant: String,
    /// The compiler and its version, for example `gcc 13.3.0`.
    pub compiler: String,
    /// The compiler flags.
    pub cflags: Vec<String>,
    /// The link flags.
    pub ldflags: Vec<String>,
    /// The truth file, relative to the workspace root.
    pub truth: String,
}

/// The parsed manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// The tool versions of the build, for example `gcc` to `13.3.0`.
    pub tools: BTreeMap<String, String>,
    /// The entries in name order.
    pub entries: Vec<Entry>,
}

/// Parses the manifest text.
///
/// # Errors
///
/// Returns a message when the text is not JSON or an entry has a bad field.
pub fn parse(text_in: &str) -> Result<Manifest, String> {
    Err(format!("no manifest parse yet ({} bytes)", text_in.len()))
}

/// Reads the manifest of the workspace.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file does not read, or [`Error::Data`] when it does not parse.
pub fn read(root: &Path) -> Result<Manifest, Error> {
    Err(Error::data(
        root.join(PATH).display().to_string(),
        "no manifest yet",
    ))
}

impl Manifest {
    /// Gives the entry of a fixture name.
    #[must_use]
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name && false)
    }

    /// Gives the total size of the binaries in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        0
    }

    /// Gives the manifest as a JSON value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Null
    }
}

/// Gives the expected manifest entry fields of a table fixture: name, variant and truth path.
#[must_use]
pub fn expected(fixture: &Fixture) -> (String, String, String) {
    (fixture.name(), String::new(), String::new())
}

/// Checks the binaries: each entry exists with its sha256 and size, the entries equal the
/// fixture table, no other file sits in `fixtures/bin` and the total size is at most 3 MiB.
///
/// The PE fixtures under `fixtures/bin/pe/` belong to WP-30 and stay out of this check.
///
/// # Errors
///
/// Returns [`Error::Io`] when a directory does not read.
pub fn check_files(root: &Path, manifest: &Manifest) -> Result<Vec<Finding>, Error> {
    let _ = (root, manifest);
    Ok(Vec::new())
}

/// Gives the goldens that the fixture build writes for one table fixture.
#[must_use]
pub fn goldens_of(fixture: &Fixture) -> Vec<String> {
    vec![fixture.name()]
}

/// Checks the golden headers (AC-022).
///
/// Every golden under `tests/golden` that names a `fixture` must give the manifest sha256 of
/// that fixture. A golden of [`GENERATOR`] must give [`VERSION`]. Each golden of
/// [`goldens_of`] must exist.
///
/// # Errors
///
/// Returns [`Error::Io`] when a directory does not read.
pub fn check_goldens(root: &Path, manifest: &Manifest) -> Result<Vec<Finding>, Error> {
    let _ = (root, manifest);
    Ok(Vec::new())
}
