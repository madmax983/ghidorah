//! The package table of design Section 2.1 and the `cargo metadata` model.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::json::{self, Value};
use crate::{Error, Finding, proc};

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
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
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
    let mut cmd = proc::cargo_cmd(&["metadata", "--format-version", "1", "--offline", "--locked"]);
    cmd.current_dir(root);
    let out = proc::run_ok(&mut cmd)?;
    parse_metadata(root, &out.stdout)
}

fn text_of(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn need_text(value: &Value, key: &str) -> Result<String, Error> {
    text_of(value, key).ok_or_else(|| Error::data("cargo metadata", format!("no `{key}` text")))
}

fn parse_dep(value: &Value) -> Result<Dep, Error> {
    let kind = match value.get("kind").and_then(Value::as_str) {
        None => DepKind::Normal,
        Some("dev") => DepKind::Dev,
        Some("build") => DepKind::Build,
        Some(other) => {
            return Err(Error::data(
                "cargo metadata",
                format!("unknown dependency kind `{other}`"),
            ));
        }
    };
    Ok(Dep {
        name: need_text(value, "name")?,
        kind,
        path: text_of(value, "path").map(PathBuf::from),
        source: text_of(value, "source"),
    })
}

fn parse_target(value: &Value) -> Result<Target, Error> {
    let kinds = value
        .get("kind")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    Ok(Target {
        name: need_text(value, "name")?,
        kinds,
        src_path: PathBuf::from(need_text(value, "src_path")?),
        edition: need_text(value, "edition")?,
    })
}

fn parse_package(value: &Value) -> Result<Package, Error> {
    let list = |key: &str| value.get(key).and_then(Value::as_array).unwrap_or_default();
    let publish_false = value
        .get("publish")
        .and_then(Value::as_array)
        .is_some_and(<[Value]>::is_empty);
    Ok(Package {
        name: need_text(value, "name")?,
        manifest_path: PathBuf::from(need_text(value, "manifest_path")?),
        edition: need_text(value, "edition")?,
        license: text_of(value, "license"),
        publish_false,
        deps: list("dependencies")
            .iter()
            .map(parse_dep)
            .collect::<Result<_, _>>()?,
        targets: list("targets")
            .iter()
            .map(parse_target)
            .collect::<Result<_, _>>()?,
    })
}

/// Parses the JSON text of `cargo metadata`.
///
/// # Errors
///
/// Returns [`Error::Data`] when the text is not valid metadata.
pub fn parse_metadata(root: &Path, text: &str) -> Result<Metadata, Error> {
    let value = json::parse(text).map_err(|e| Error::data("cargo metadata", e.to_string()))?;
    let mut packages = value
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::data("cargo metadata", "no `packages` array"))?
        .iter()
        .map(parse_package)
        .collect::<Result<Vec<_>, _>>()?;
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Metadata {
        root: root.to_path_buf(),
        packages,
    })
}

const AC_001A: &str = "AC-001a";

/// AC-001a: every package is a row of [`PACKAGES`] at its listed directory.
#[must_use]
pub fn check_packages(meta: &Metadata) -> Vec<Finding> {
    let mut found = Vec::new();
    for package in &meta.packages {
        let dir = package.dir(&meta.root);
        let manifest = format!("{dir}/Cargo.toml");
        match spec(&package.name) {
            None => found.push(Finding::new(
                AC_001A,
                manifest,
                0,
                format!("package `{}` is not in design Section 2.1", package.name),
            )),
            Some(row) if row.dir != dir => found.push(Finding::new(
                AC_001A,
                manifest,
                0,
                format!("package `{}` must live in `{}`", package.name, row.dir),
            )),
            Some(_) => {}
        }
    }
    found
}

/// AC-001c: every dependency is a workspace package at a local path.
#[must_use]
pub fn check_workspace_deps(meta: &Metadata) -> Vec<Finding> {
    let mut found = Vec::new();
    for package in &meta.packages {
        let manifest = format!("{}/Cargo.toml", package.dir(&meta.root));
        for dep in &package.deps {
            let local = dep
                .path
                .as_ref()
                .is_some_and(|p| spec(&dep.name).is_some_and(|row| rel(&meta.root, p) == row.dir));
            if dep.source.is_some() || !local {
                found.push(Finding::new(
                    "AC-001c",
                    manifest.clone(),
                    0,
                    format!("dependency `{}` is not a workspace package", dep.name),
                ));
            }
        }
    }
    found
}

/// AC-001e: every package sets `publish = false` and `license = "Apache-2.0"`.
#[must_use]
pub fn check_publish_license(meta: &Metadata) -> Vec<Finding> {
    let mut found = Vec::new();
    for package in &meta.packages {
        let manifest = format!("{}/Cargo.toml", package.dir(&meta.root));
        if !package.publish_false {
            let detail = format!("package `{}` must set `publish = false`", package.name);
            found.push(Finding::new("AC-001e", manifest.clone(), 0, detail));
        }
        if package.license.as_deref() != Some("Apache-2.0") {
            let detail = format!(
                "package `{}` must set `license = \"Apache-2.0\"`",
                package.name
            );
            found.push(Finding::new("AC-001e", manifest, 0, detail));
        }
    }
    found
}

/// AC-007b: every package and every target uses edition 2024.
#[must_use]
pub fn check_edition(meta: &Metadata) -> Vec<Finding> {
    let mut found = Vec::new();
    for package in &meta.packages {
        let manifest = format!("{}/Cargo.toml", package.dir(&meta.root));
        if package.edition != "2024" {
            let detail = format!(
                "package `{}` uses edition {}",
                package.name, package.edition
            );
            found.push(Finding::new("AC-007b", manifest.clone(), 0, detail));
        }
        for target in package.targets.iter().filter(|t| t.edition != "2024") {
            let detail = format!("target `{}` uses edition {}", target.name, target.edition);
            found.push(Finding::new("AC-007b", manifest.clone(), 0, detail));
        }
    }
    found
}

/// Gives the names of `name` and of every package that it reaches through normal and build edges.
#[must_use]
pub fn closure(meta: &Metadata, name: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut work = vec![name.to_owned()];
    while let Some(next) = work.pop() {
        let Some(package) = meta.package(&next) else {
            continue;
        };
        if !seen.insert(next) {
            continue;
        }
        for dep in package.deps.iter().filter(|d| d.kind != DepKind::Dev) {
            if !seen.contains(&dep.name) {
                work.push(dep.name.clone());
            }
        }
    }
    seen
}
