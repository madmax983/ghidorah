//! Shared helpers of the kernel proof tests (AC-034, AC-035).
//!
//! The tests use the xtask JSON parser, the xtask comment stripper and the xtask tree hash.
//! `#[path]` includes them, so the tests and `xtask verify` use one definition.

#![allow(dead_code, reason = "the tests use a part of the included xtask files")]
#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]

#[path = "../../../../xtask/src/json.rs"]
pub mod json;
#[path = "../../../../xtask/src/rustsrc.rs"]
pub mod rustsrc;
#[path = "../../../../xtask/src/verify/tree.rs"]
pub mod tree;

use std::path::{Path, PathBuf};

/// Gives the workspace root.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives each `.rs` file under `crates/kernel/src` as a pair of a relative path and its text.
pub fn kernel_sources() -> Vec<(String, String)> {
    tree::tree_files(&root())
        .expect("the kernel and spec sources are readable")
        .into_iter()
        .filter(|(path, _)| path.starts_with("crates/kernel/src/"))
        .map(|(path, bytes)| (path, String::from_utf8(bytes).expect("the source is UTF-8")))
        .collect()
}

/// Tells if the environment has `GHIDORAH_REQUIRE_PROOFS=1`.
pub fn proofs_required() -> bool {
    std::env::var("GHIDORAH_REQUIRE_PROOFS").is_ok_and(|v| v == "1")
}

/// Reads the proof record, or `None` when it is missing or not valid JSON.
pub fn results() -> Option<json::Value> {
    let text = std::fs::read_to_string(root().join(tree::RESULTS_PATH)).ok()?;
    json::parse(&text).ok()
}
