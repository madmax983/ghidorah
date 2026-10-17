//! The allowed-edge table of design Section 2.2 and the `xtask deps` command.
//!
//! The table is the contract. `docs/architecture/crates.mmd` is its generated picture.
//! A new edge needs a design change first, then one line in [`ALLOWED`].

use std::path::Path;

use crate::json::Value;
use crate::workspace::{DepKind, Metadata};
use crate::{Error, Finding};

/// The generated crate graph, relative to the workspace root.
pub const MMD_PATH: &str = "docs/architecture/crates.mmd";

/// The allowed normal edges `(from, to)` by package name.
pub const ALLOWED: &[(&str, &str)] = &[
    ("ghidorah-kernel", "ghidorah-spec"),
    ("ghidorah-base", "ghidorah-kernel"),
    ("ghidorah-loader", "ghidorah-base"),
    ("ghidorah-loader", "ghidorah-kernel"),
    ("ghidorah-ir", "ghidorah-base"),
    ("ghidorah-ir", "ghidorah-kernel"),
    ("ghidorah-x86", "ghidorah-ir"),
    ("ghidorah-x86", "ghidorah-base"),
    ("ghidorah-types", "ghidorah-base"),
    ("ghidorah-db", "ghidorah-base"),
    ("ghidorah-db", "ghidorah-kernel"),
    ("ghidorah-db", "ghidorah-json"),
    ("ghidorah-db", "ghidorah-loader"),
    ("ghidorah-db", "ghidorah-types"),
    ("ghidorah-analysis", "ghidorah-db"),
    ("ghidorah-analysis", "ghidorah-ir"),
    ("ghidorah-analysis", "ghidorah-x86"),
    ("ghidorah-analysis", "ghidorah-types"),
    ("ghidorah-analysis", "ghidorah-loader"),
    ("ghidorah-decomp", "ghidorah-analysis"),
    ("ghidorah-decomp", "ghidorah-ir"),
    ("ghidorah-decomp", "ghidorah-db"),
    ("ghidorah-decomp", "ghidorah-types"),
    ("ghidorah-tools", "ghidorah-decomp"),
    ("ghidorah-tools", "ghidorah-analysis"),
    ("ghidorah-tools", "ghidorah-db"),
    ("ghidorah-tools", "ghidorah-x86"),
    ("ghidorah-tools", "ghidorah-types"),
    ("ghidorah-tools", "ghidorah-loader"),
    ("ghidorah-tools", "ghidorah-json"),
    ("ghidorah-tools", "ghidorah-base"),
    ("ghidorah", "ghidorah-tools"),
    ("ghidorah", "ghidorah-json"),
    ("ghidorah", "ghidorah-base"),
    ("ghidorah-eval", "ghidorah-tools"),
    ("ghidorah-eval", "ghidorah-json"),
    ("xtask", "ghidorah-json"),
    ("xtask", "ghidorah-base"),
    ("xtask", "ghidorah-testkit"),
];

/// The allowed dev edges beyond [`ALLOWED`] and [`DEV_ANY`].
pub const DEV_ALLOWED: &[(&str, &str)] = &[("ghidorah-loader", "ghidorah-oracle")];

/// Every package except this one can take it as a dev-dependency.
pub const DEV_ANY: &str = "ghidorah-testkit";

/// One dependency edge between two workspace packages.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Edge {
    /// The package that has the dependency.
    pub from: String,
    /// The package that it depends on.
    pub to: String,
    /// The edge kind.
    pub kind: DepKind,
}

/// Gives every edge between workspace packages, sorted.
#[must_use]
pub fn edges(meta: &Metadata) -> Vec<Edge> {
    let _ = meta;
    Vec::new()
}

/// Tells if the table allows an edge.
#[must_use]
pub fn is_allowed(from: &str, to: &str, kind: DepKind) -> bool {
    let _ = (from, to, kind);
    true
}

/// AC-003: gives one finding for each edge that the table does not allow.
#[must_use]
pub fn check_edges(edges: &[Edge]) -> Vec<Finding> {
    let _ = edges;
    Vec::new()
}

/// Renders the allowed-edge table as a Mermaid graph.
#[must_use]
pub fn render() -> String {
    String::new()
}

/// AC-003: gives a finding when `crates.mmd` differs from [`render`].
#[must_use]
pub fn check_mmd(root: &Path) -> Vec<Finding> {
    let _ = root;
    Vec::new()
}

/// Runs `xtask deps [--check]`.
///
/// Without `--check`, the command writes `crates.mmd` again.
///
/// # Errors
///
/// Returns an error when cargo metadata fails or the file write fails.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let _ = (root, args);
    Err(Error::Usage("deps".to_owned()))
}
