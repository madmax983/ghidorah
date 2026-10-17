//! Leaf functions and their leaf-driver vectors (design Section 13.8, AC-072).
//!
//! A fixture source marks a leaf function with a line that starts with `LEAF`:
//!
//! ```c
//! LEAF uint64_t gcd(uint64_t a, uint64_t b) {
//! ```
//!
//! The types are the `<stdint.h>` integer types of 8 to 64 bits. A leaf function takes 1 to 3
//! arguments. The build writes `leaf_list.h` for `fixtures/src/leaf_driver.c` and runs the
//! driver. The golden `tests/golden/semantics/leaf/<build>.jsonl` holds [`CASES`] lines per leaf
//! function: `{"fn":"gcd","args":["0x..","0x.."],"ret":"0x.."}`. Each value is the bit pattern
//! at the width of its type.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use ghidorah_testkit::golden;

use super::manifest::Manifest;
use crate::json::{self, Value};
use crate::{Error, Finding};

/// The number of driver calls per leaf function.
pub const CASES: usize = 1000;

/// The golden directory of the leaf vectors, relative to the workspace root.
pub const VECTOR_DIR: &str = "tests/golden/semantics/leaf";

/// An integer type of a leaf function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntType {
    /// `uint8_t`.
    U8,
    /// `uint16_t`.
    U16,
    /// `uint32_t`.
    U32,
    /// `uint64_t`.
    U64,
    /// `int8_t`.
    I8,
    /// `int16_t`.
    I16,
    /// `int32_t`.
    I32,
    /// `int64_t`.
    I64,
}

/// The C names and the short names of the types.
const TYPES: &[(&str, &str, IntType)] = &[
    ("uint8_t", "u8", IntType::U8),
    ("uint16_t", "u16", IntType::U16),
    ("uint32_t", "u32", IntType::U32),
    ("uint64_t", "u64", IntType::U64),
    ("int8_t", "i8", IntType::I8),
    ("int16_t", "i16", IntType::I16),
    ("int32_t", "i32", IntType::I32),
    ("int64_t", "i64", IntType::I64),
];

impl IntType {
    /// Gives the type of a C type name.
    #[must_use]
    pub fn from_c(name: &str) -> Option<Self> {
        TYPES.iter().find(|t| t.0 == name).map(|t| t.2)
    }

    /// Gives the C type name, for example `uint64_t`.
    #[must_use]
    pub fn c_name(self) -> &'static str {
        TYPES.iter().find(|t| t.2 == self).map_or("", |t| t.0)
    }

    /// Gives the short name, for example `u64`.
    #[must_use]
    pub fn short(self) -> &'static str {
        TYPES.iter().find(|t| t.2 == self).map_or("", |t| t.1)
    }

    /// Gives the width in bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::U8 | Self::I8 => 8,
            Self::U16 | Self::I16 => 16,
            Self::U32 | Self::I32 => 32,
            Self::U64 | Self::I64 => 64,
        }
    }
}

/// One leaf function of a fixture source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafFn {
    /// The function name.
    pub name: String,
    /// The result type.
    pub ret: IntType,
    /// The argument types, 1 to 3.
    pub args: Vec<IntType>,
}

impl LeafFn {
    /// Gives the signature text, for example `u64(u64,u64)`.
    #[must_use]
    pub fn sig(&self) -> String {
        let args: Vec<&str> = self.args.iter().map(|a| a.short()).collect();
        format!("{}({})", self.ret.short(), args.join(","))
    }

    /// Gives the `leaf_list.h` line of the function.
    #[must_use]
    pub fn list_line(&self) -> String {
        let mut parts = vec![self.name.clone(), self.ret.c_name().to_owned()];
        parts.extend(self.args.iter().map(|a| a.c_name().to_owned()));
        format!("LEAF{}({})", self.args.len(), parts.join(", "))
    }
}

/// A `LEAF` line that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafError {
    /// The 1-based line number.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for LeafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for LeafError {}

fn parse_line(text: &str) -> Result<LeafFn, String> {
    let body = text.strip_prefix("LEAF ").ok_or("no `LEAF ` prefix")?;
    let (decl, after) = body.split_once('(').ok_or("no `(`")?;
    let (args, _) = after.split_once(')').ok_or("no `)`")?;
    let mut words = decl.split_whitespace();
    let ret_c = words.next().ok_or("no result type")?;
    let name = words.next().ok_or("no function name")?;
    let ret = IntType::from_c(ret_c).ok_or_else(|| format!("unknown type `{ret_c}`"))?;
    let mut types = Vec::new();
    for arg in args.split(',') {
        let ty = arg.split_whitespace().next().unwrap_or("");
        types.push(IntType::from_c(ty).ok_or_else(|| format!("unknown type `{ty}`"))?);
    }
    if !(1..=3).contains(&types.len()) {
        return Err("a leaf function takes 1 to 3 arguments".to_owned());
    }
    Ok(LeafFn {
        name: name.to_owned(),
        ret,
        args: types,
    })
}

/// Gives the leaf functions of a C source, in source order.
///
/// # Errors
///
/// Returns a [`LeafError`] for a `LEAF` line with an unknown type or a bad shape.
pub fn parse_source(text: &str) -> Result<Vec<LeafFn>, LeafError> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.starts_with("LEAF ") {
            out.push(parse_line(line).map_err(|message| LeafError {
                line: i + 1,
                message,
            })?);
        }
    }
    Ok(out)
}

/// Gives the text of `leaf_list.h` for the driver.
#[must_use]
pub fn list_header(fns: &[LeafFn]) -> String {
    fns.iter().map(|f| f.list_line() + "\n").collect()
}

/// Gives the golden path of the vectors of a build, relative to the workspace root.
#[must_use]
pub fn vector_path(build: &str) -> String {
    format!("{VECTOR_DIR}/{build}.jsonl")
}

fn hex_bits(value: &Value, bits: u32) -> bool {
    let Some(text) = value.as_str().and_then(|t| t.strip_prefix("0x")) else {
        return false;
    };
    u64::from_str_radix(text, 16).is_ok_and(|v| bits == 64 || v >> bits == 0)
}

/// Checks the vector lines of one build against its leaf functions.
///
/// Each function needs exactly [`CASES`] lines with the right argument count and widths.
#[must_use]
pub fn check_lines(rel: &str, body: &str, fns: &[LeafFn]) -> Vec<Finding> {
    let bad = |line: usize, detail: String| Finding::new("WP-06", rel, line, detail);
    let mut found = Vec::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, line) in body.lines().enumerate() {
        let n = i + 2;
        let Ok(value) = json::parse(line) else {
            found.push(bad(n, "the line is not JSON".to_owned()));
            continue;
        };
        let name = value.get("fn").and_then(Value::as_str).unwrap_or("");
        let Some(f) = fns.iter().find(|f| f.name == name) else {
            found.push(bad(n, format!("unknown leaf function `{name}`")));
            continue;
        };
        let args = value.get("args").and_then(Value::as_array).unwrap_or(&[]);
        let widths_ok = args.len() == f.args.len()
            && args.iter().zip(&f.args).all(|(v, t)| hex_bits(v, t.bits()));
        let ret_ok = value.get("ret").is_some_and(|v| hex_bits(v, f.ret.bits()));
        if !widths_ok || !ret_ok {
            found.push(bad(n, format!("bad arguments or result for `{name}`")));
        }
        *counts.entry(f.name.as_str()).or_default() += 1;
    }
    for f in fns {
        let count = counts.get(f.name.as_str()).copied().unwrap_or(0);
        if count != CASES {
            found.push(bad(
                0,
                format!("`{}` has {count} vectors, not {CASES}", f.name),
            ));
        }
    }
    found
}

/// Gives the leaf functions that a truth file lists: name and signature.
fn truth_leafs(truth: &Value) -> Vec<(String, String)> {
    truth
        .get("leaf_functions")
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .map(|v| {
            let text = |k| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            (text("name"), text("sig"))
        })
        .collect()
}

/// Checks that every leaf function of every leaf-vector build has its vectors.
///
/// The leaf functions come from the `LEAF` lines of the sources. Each such build needs a truth
/// file that lists them and a golden with [`CASES`] lines per function.
///
/// # Errors
///
/// Returns an error when a source or a truth file does not read or parse.
pub fn check_vectors(root: &Path, manifest: &Manifest) -> Result<Vec<Finding>, Error> {
    let mut found = Vec::new();
    let mut builds = Vec::new();
    for fixture in super::spec::fixtures() {
        if fixture.variant.is_none() && fixture.build.leaf_vectors {
            builds.push(fixture);
        }
    }
    for fixture in builds {
        let mut fns = Vec::new();
        for src in fixture.program.sources {
            let rel = format!("{}/{src}", super::SRC_DIR);
            let text = std::fs::read_to_string(root.join(&rel)).map_err(|e| Error::io(&rel, e))?;
            fns.extend(parse_source(&text).map_err(|e| Error::data(&rel, e.to_string()))?);
        }
        if fns.is_empty() {
            continue;
        }
        let name = fixture.truth_name();
        let truth = super::truth::read(root, &name)?;
        let want: Vec<(String, String)> = fns.iter().map(|f| (f.name.clone(), f.sig())).collect();
        if truth_leafs(&truth) != want {
            found.push(Finding::new(
                "WP-06",
                super::truth::path(&name),
                0,
                "`leaf_functions` differs from the LEAF lines of the sources",
            ));
        }
        let rel = vector_path(&name);
        match golden::read(&root.join(&rel)) {
            Ok((header, body)) => {
                if manifest.entry(&name).is_none() || header.field("fixture") != Some(name.as_str())
                {
                    found.push(Finding::new(
                        "WP-06",
                        &rel,
                        1,
                        "the header names another fixture",
                    ));
                }
                found.extend(check_lines(&rel, &body, &fns));
            }
            Err(e) => found.push(Finding::new("WP-06", &rel, 0, e.to_string())),
        }
    }
    Ok(found)
}
