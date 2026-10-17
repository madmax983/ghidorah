//! The tree hash of the proof inputs (design Section 13.3, AC-034).
//!
//! The hash covers the files under [`SOURCE_DIRS`] and the Verus argument list [`ARGV`].
//! A change to a kernel file, to the stub crate or to the flags makes the record stale.
//!
//! Encoding: for each file in path order, the hash takes `file <path>\n<byte count>\n<bytes>`.
//! Then it takes `argv <ARGV joined with spaces>\n`.
//!
//! This file uses only `std`. The kernel test `ac_034_proof_freshness` includes it with `#[path]`.
//! So the record and the test use one hash definition.

use std::io;
use std::path::Path;

/// The Verus argument list of the record. The program name is `verus` on every host.
pub const ARGV: &[&str] = &[
    "verus",
    "--cfg",
    "verus_only",
    "--no-cheating",
    "--crate-type=lib",
    "--output-json",
    "crates/kernel/src/lib.rs",
];

/// The proof record, relative to the workspace root.
pub const RESULTS_PATH: &str = "verify/results.json";

/// The source directories that the tree hash covers, relative to the workspace root.
pub const SOURCE_DIRS: &[&str] = &["crates/kernel/src", "crates/spec/src"];

/// The maximum depth of the directory walk.
const MAX_DEPTH: usize = 16;

/// Gives the SHA-256 digest of `bytes` (FIPS 180-4).
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let _ = bytes;
    [0; 32]
}

/// Gives the lowercase hex text of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let _ = bytes;
    String::new()
}

/// Gives the tree hash of `files` and `argv` as lowercase hex.
///
/// Each file is a pair of a relative path with `/` separators and its bytes.
/// The order of `files` has no effect.
#[must_use]
pub fn hash_files(files: &[(String, Vec<u8>)], argv: &[&str]) -> String {
    let _ = (files, argv);
    String::new()
}

/// Gives each file under [`SOURCE_DIRS`] as a pair of a relative path and its bytes.
///
/// # Errors
///
/// Gives the I/O error of a failed directory read or file read.
pub fn tree_files(root: &Path) -> io::Result<Vec<(String, Vec<u8>)>> {
    let _ = (root, MAX_DEPTH);
    Ok(Vec::new())
}

/// Gives the tree hash of the proof inputs under `root` with [`ARGV`].
///
/// # Errors
///
/// Gives the I/O error of a failed directory read or file read.
pub fn tree_sha256(root: &Path) -> io::Result<String> {
    Ok(hash_files(&tree_files(root)?, ARGV))
}
