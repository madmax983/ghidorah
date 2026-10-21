//! The fixture manifest `fixtures/manifest.json` and the checks of AC-022.
//!
//! Format: `{ generator, version, tools: { <tool>: <version> }, total_bytes, fixtures: [entry] }`.
//! An entry is `{ name, path, sha256, size, tier, program, build, variant, compiler, cflags,
//! ldflags, truth }`. `variant` is `none`, `stripped`, `noeh` or `noshdr`. Entries are in name
//! order. The PE fixtures of WP-30 live under `fixtures/bin/pe/` with their own entries.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ghidorah_testkit::golden;

use super::spec::{self, Fixture};
use super::{BIN_DIR, GENERATOR, GOLDEN_AREAS, MAX_TOTAL_BYTES, VERSION};
use crate::json::{self, Value};
use crate::verify::tree::{hex, sha256};
use crate::workspace::rel;
use crate::{Error, Finding};

/// The manifest path, relative to the workspace root.
pub const PATH: &str = "fixtures/manifest.json";

/// The golden root, relative to the workspace root.
pub const GOLDEN_ROOT: &str = "tests/golden";

/// The depth limit of the golden directory walk.
const MAX_DEPTH: usize = 8;

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

fn text(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("`{key}` is not a string"))
}

fn texts(v: &Value, key: &str) -> Result<Vec<String>, String> {
    let items = v
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("`{key}` is not an array"))?;
    items
        .iter()
        .map(|i| {
            i.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("`{key}` holds a non-string"))
        })
        .collect()
}

fn entry(v: &Value) -> Result<Entry, String> {
    Ok(Entry {
        name: text(v, "name")?,
        path: text(v, "path")?,
        sha256: text(v, "sha256")?,
        size: v
            .get("size")
            .and_then(Value::as_u64)
            .ok_or("`size` is not a number")?,
        tier: text(v, "tier")?,
        program: text(v, "program")?,
        build: text(v, "build")?,
        variant: text(v, "variant")?,
        compiler: text(v, "compiler")?,
        cflags: texts(v, "cflags")?,
        ldflags: texts(v, "ldflags")?,
        truth: text(v, "truth")?,
    })
}

/// Parses the manifest text.
///
/// # Errors
///
/// Returns a message when the text is not JSON or an entry has a bad field.
pub fn parse(text_in: &str) -> Result<Manifest, String> {
    let value = json::parse(text_in).map_err(|e| e.to_string())?;
    let tools = value
        .get("tools")
        .and_then(Value::as_object)
        .ok_or("`tools` is not an object")?
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_owned()))
        .collect();
    let entries = value
        .get("fixtures")
        .and_then(Value::as_array)
        .ok_or("`fixtures` is not an array")?
        .iter()
        .map(entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Manifest { tools, entries })
}

/// Reads the manifest of the workspace.
///
/// # Errors
///
/// Returns [`Error::Io`] when the file does not read, or [`Error::Data`] when it does not parse.
pub fn read(root: &Path) -> Result<Manifest, Error> {
    let path = root.join(PATH);
    let body = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    parse(&body).map_err(|m| Error::data(PATH, m))
}

impl Manifest {
    /// Gives the entry of a fixture name.
    #[must_use]
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Gives the total size of the binaries in bytes.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }

    /// Gives the manifest as a JSON value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let strings = |v: &[String]| {
            Value::from(
                v.iter()
                    .map(|s| Value::from(s.as_str()))
                    .collect::<Vec<_>>(),
            )
        };
        let fixtures: Vec<Value> = self
            .entries
            .iter()
            .map(|e| {
                Value::object([
                    ("name", Value::from(e.name.as_str())),
                    ("path", Value::from(e.path.as_str())),
                    ("sha256", Value::from(e.sha256.as_str())),
                    ("size", Value::from(e.size)),
                    ("tier", Value::from(e.tier.as_str())),
                    ("program", Value::from(e.program.as_str())),
                    ("build", Value::from(e.build.as_str())),
                    ("variant", Value::from(e.variant.as_str())),
                    ("compiler", Value::from(e.compiler.as_str())),
                    ("cflags", strings(&e.cflags)),
                    ("ldflags", strings(&e.ldflags)),
                    ("truth", Value::from(e.truth.as_str())),
                ])
            })
            .collect();
        let tools = self
            .tools
            .iter()
            .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
            .collect();
        Value::object([
            ("generator", Value::from(GENERATOR)),
            ("version", Value::from(VERSION)),
            ("tools", Value::Object(tools)),
            ("total_bytes", Value::from(self.total_bytes())),
            ("fixtures", Value::from(fixtures)),
        ])
    }
}

/// Gives the expected manifest entry fields of a table fixture: name, variant and truth path.
#[must_use]
pub fn expected(fixture: &Fixture) -> (String, String, String) {
    let variant = fixture.variant.map_or("none", spec::Variant::suffix);
    (
        fixture.name(),
        variant.to_owned(),
        super::truth::path(&fixture.truth_name()),
    )
}

fn list_files(root: &Path, dir: &Path, depth: usize, out: &mut Vec<String>) -> Result<(), Error> {
    if depth > MAX_DEPTH || !dir.is_dir() {
        return Ok(());
    }
    for item in std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))? {
        let path = item.map_err(|e| Error::io(dir, e))?.path();
        if path.is_dir() {
            list_files(root, &path, depth + 1, out)?;
        } else {
            out.push(rel(root, &path));
        }
    }
    Ok(())
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
    let bad = |path: &str, detail: String| Finding::new("AC-022", path, 0, detail);
    let mut found = Vec::new();
    for e in &manifest.entries {
        match std::fs::read(root.join(&e.path)) {
            Ok(bytes) => {
                if hex(&sha256(&bytes)) != e.sha256 {
                    found.push(bad(&e.path, format!("sha256 differs from {PATH}")));
                }
                if u64::try_from(bytes.len()).ok() != Some(e.size) {
                    found.push(bad(&e.path, format!("size differs from {PATH}")));
                }
            }
            Err(err) => found.push(bad(&e.path, err.to_string())),
        }
    }
    let table: BTreeSet<(String, String, String)> = spec::fixtures().iter().map(expected).collect();
    let listed: BTreeSet<(String, String, String)> = manifest
        .entries
        .iter()
        .filter(|e| !e.path.starts_with("fixtures/bin/pe/"))
        .map(|e| (e.name.clone(), e.variant.clone(), e.truth.clone()))
        .collect();
    for missing in table.difference(&listed) {
        found.push(bad(PATH, format!("no entry for fixture `{}`", missing.0)));
    }
    for extra in listed.difference(&table) {
        found.push(bad(
            PATH,
            format!("entry `{}` is not in the fixture table", extra.0),
        ));
    }
    let mut files = Vec::new();
    list_files(root, &root.join(BIN_DIR), 0, &mut files)?;
    let known: BTreeSet<&str> = manifest.entries.iter().map(|e| e.path.as_str()).collect();
    for file in files.iter().filter(|f| !f.starts_with("fixtures/bin/pe/")) {
        if !known.contains(file.as_str()) {
            found.push(bad(file, "the file has no manifest entry".to_owned()));
        }
    }
    if manifest.total_bytes() > MAX_TOTAL_BYTES {
        found.push(bad(
            PATH,
            format!("the fixtures take more than {MAX_TOTAL_BYTES} bytes"),
        ));
    }
    Ok(found)
}

/// Gives the goldens that the fixture build writes for one table fixture.
#[must_use]
pub fn goldens_of(fixture: &Fixture) -> Vec<String> {
    let name = fixture.name();
    let mut out = vec![format!("{GOLDEN_ROOT}/loader/{name}.readelf.txt")];
    if fixture.variant == Some(spec::Variant::NoShdr) {
        out.push(format!("{GOLDEN_ROOT}/loader/{name}.dynrel.txt"));
    }
    if fixture.has_symtab() {
        out.push(format!("{GOLDEN_ROOT}/objdump/{name}.txt"));
        out.push(format!("{GOLDEN_ROOT}/ehframe/{name}.txt"));
    }
    out
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
    let mut found = Vec::new();
    let mut files = Vec::new();
    list_files(root, &root.join(GOLDEN_ROOT), 0, &mut files)?;
    let owned = |f: &str| {
        GOLDEN_AREAS
            .iter()
            .any(|a| f.starts_with(&format!("{GOLDEN_ROOT}/{a}/")))
            && !f.starts_with(&format!("{GOLDEN_ROOT}/loader/pe/"))
    };
    for file in &files {
        let header = match golden::read(&root.join(file)) {
            Ok((header, _)) => header,
            Err(e) => {
                if owned(file) {
                    found.push(Finding::new("AC-022", file, 1, e.to_string()));
                }
                continue;
            }
        };
        if header.generator() == GENERATOR && header.version() != VERSION {
            found.push(Finding::new(
                "AC-022",
                file,
                1,
                format!("generator version is not {VERSION}"),
            ));
        }
        match header.field("fixture") {
            Some(name) => match manifest.entry(name) {
                Some(e) if header.field("fixture_sha256") == Some(e.sha256.as_str()) => {}
                Some(_) => found.push(Finding::new(
                    "AC-022",
                    file,
                    1,
                    "fixture_sha256 differs from the manifest",
                )),
                None => found.push(Finding::new(
                    "AC-022",
                    file,
                    1,
                    format!("no manifest entry for `{name}`"),
                )),
            },
            None if owned(file) => found.push(Finding::new(
                "AC-022",
                file,
                1,
                "the header names no fixture",
            )),
            None => {}
        }
    }
    let have: BTreeSet<&str> = files.iter().map(String::as_str).collect();
    for fixture in spec::fixtures() {
        for want in goldens_of(&fixture) {
            if !have.contains(want.as_str()) {
                found.push(Finding::new("AC-022", &want, 0, "the golden is missing"));
            }
        }
    }
    Ok(found)
}
