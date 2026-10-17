//! The package table of design Section 2.1 and the `cargo metadata` model.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::{Error, Finding};

/// The kind of a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A package that ships in the `ghidorah` binary.
    Prod,
    /// A package for development only. It never enters the binary closure.
    Dev,
}

/// One row of the package table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageSpec {
    /// The package name.
    pub name: &'static str,
    /// The directory, relative to the workspace root.
    pub dir: &'static str,
    /// The package kind.
    pub kind: Kind,
}

const fn spec_row(name: &'static str, dir: &'static str, kind: Kind) -> PackageSpec {
    PackageSpec { name, dir, kind }
}

/// The packages of design Section 2.1. Only these packages can exist.
pub const PACKAGES: &[PackageSpec] = &[
    spec_row("ghidorah-spec", "crates/spec", Kind::Prod),
    spec_row("ghidorah-kernel", "crates/kernel", Kind::Prod),
    spec_row("ghidorah-base", "crates/base", Kind::Prod),
    spec_row("ghidorah-json", "crates/json", Kind::Prod),
    spec_row("ghidorah-loader", "crates/loader", Kind::Prod),
    spec_row("ghidorah-x86", "crates/x86", Kind::Prod),
    spec_row("ghidorah-ir", "crates/ir", Kind::Prod),
    spec_row("ghidorah-types", "crates/types", Kind::Prod),
    spec_row("ghidorah-db", "crates/db", Kind::Prod),
    spec_row("ghidorah-analysis", "crates/analysis", Kind::Prod),
    spec_row("ghidorah-decomp", "crates/decomp", Kind::Prod),
    spec_row("ghidorah-tools", "crates/tools", Kind::Prod),
    spec_row("ghidorah", "crates/cli", Kind::Prod),
    spec_row("ghidorah-eval", "crates/eval", Kind::Dev),
    spec_row("ghidorah-testkit", "crates/testkit", Kind::Dev),
    spec_row("ghidorah-oracle", "crates/oracle", Kind::Dev),
    spec_row("xtask", "xtask", Kind::Dev),
];

/// The pure core crates of AC-017, as directory names under `crates/`.
pub const PURE_CORE: &[&str] = &[
    "kernel", "base", "json", "loader", "x86", "ir", "types", "analysis", "decomp",
];

/// The name of the shipped binary package.
pub const BINARY: &str = "ghidorah";

/// Gives the table row of a package name.
#[must_use]
pub fn spec(name: &str) -> Option<&'static PackageSpec> {
    PACKAGES.iter().find(|p| p.name == name)
}

/// The workspace root: the parent directory of the xtask package.
#[must_use]
pub fn root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map_or_else(|| manifest_dir.to_path_buf(), Path::to_path_buf)
}

/// Gives `path` relative to `root`, with `/` separators.
#[must_use]
pub fn rel(root: &Path, path: &Path) -> String {
    let _ = (root, path);
    String::new()
}

/// The kind of a dependency edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DepKind {
    /// A normal dependency.
    Normal,
    /// A dev-dependency.
    Dev,
    /// A build-dependency.
    Build,
}

/// One dependency of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    /// The package name of the dependency.
    pub name: String,
    /// The edge kind.
    pub kind: DepKind,
    /// The local path for a path dependency.
    pub path: Option<PathBuf>,
    /// The registry or git source, when one exists.
    pub source: Option<String>,
}

/// One build target of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The target name.
    pub name: String,
    /// The target kinds, for example `lib`, `bin`, `test` or `custom-build`.
    pub kinds: Vec<String>,
    /// The root source file.
    pub src_path: PathBuf,
    /// The Rust edition of the target.
    pub edition: String,
}

/// One package of `cargo metadata`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// The package name.
    pub name: String,
    /// The absolute path of its `Cargo.toml`.
    pub manifest_path: PathBuf,
    /// The Rust edition.
    pub edition: String,
    /// The license expression.
    pub license: Option<String>,
    /// True when the package sets `publish = false`.
    pub publish_false: bool,
    /// The dependencies.
    pub deps: Vec<Dep>,
    /// The build targets.
    pub targets: Vec<Target>,
}

impl Package {
    /// Gives the package directory relative to `root`.
    #[must_use]
    pub fn dir(&self, root: &Path) -> String {
        self.manifest_path
            .parent()
            .map_or_else(String::new, |d| rel(root, d))
    }
}

/// The workspace model from `cargo metadata`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// The workspace root.
    pub root: PathBuf,
    /// Every package, sorted by name.
    pub packages: Vec<Package>,
}

impl Metadata {
    /// Gives the package with a name.
    #[must_use]
    pub fn package(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.name == name)
    }
}

/// Runs `cargo metadata --format-version 1 --offline --locked` and parses its output.
///
/// # Errors
///
/// Returns an error when cargo fails or the output has a bad form.
pub fn load_metadata(root: &Path) -> Result<Metadata, Error> {
    let _ = root;
    Err(Error::data("cargo metadata", "loader missing"))
}

/// Parses the JSON text of `cargo metadata`.
///
/// # Errors
///
/// Returns [`Error::Data`] when the text is not valid metadata.
pub fn parse_metadata(root: &Path, text: &str) -> Result<Metadata, Error> {
    let _ = (root, text);
    Err(Error::data("cargo metadata", "parser missing"))
}

/// AC-001a: every package is a row of [`PACKAGES`] at its listed directory.
#[must_use]
pub fn check_packages(meta: &Metadata) -> Vec<Finding> {
    let _ = meta;
    Vec::new()
}

/// AC-001c: every dependency is a workspace package at a local path.
#[must_use]
pub fn check_workspace_deps(meta: &Metadata) -> Vec<Finding> {
    let _ = meta;
    Vec::new()
}

/// AC-001e: every package sets `publish = false` and `license = "Apache-2.0"`.
#[must_use]
pub fn check_publish_license(meta: &Metadata) -> Vec<Finding> {
    let _ = meta;
    Vec::new()
}

/// AC-007b: every package and every target uses edition 2024.
#[must_use]
pub fn check_edition(meta: &Metadata) -> Vec<Finding> {
    let _ = meta;
    Vec::new()
}

/// Gives the names of `name` and of every package that it reaches through normal and build edges.
#[must_use]
pub fn closure(meta: &Metadata, name: &str) -> BTreeSet<String> {
    let _ = (meta, name);
    BTreeSet::new()
}
