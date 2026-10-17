//! The AC table of design Section 15: the evidence grammar, the Needs order and `xtask ac`.
//!
//! Evidence grammar (ADR-0020):
//!
//! | Kind | Form |
//! |---|---|
//! | test | `test:<crate>::<fn>@T1` or `@T2` |
//! | cmd | `cmd:<argv>` |
//! | xtask | `xtask:<subcommand>#<pointer> <op> <value>` |
//! | record | `record:<file>#<pointer>@sha256=<input>` |

use std::path::Path;

use crate::json::Value;
use crate::{Error, Finding};

/// The design document, relative to the workspace root.
pub const DESIGN_PATH: &str = "docs/design.md";

/// The pair order of the work packages (design Section 14.3, revision 3).
///
/// Pairs merge in this order. Inside a pair, the first WP merges first and the second WP rebases.
/// WP-29 and WP-30 come after the Increment D pairs and before the hardening pair.
pub const PAIRS: &[(&str, &[&str])] = &[
    ("P1", &["01", "02"]),
    ("P2", &["03", "04"]),
    ("P3", &["05", "06"]),
    ("P4", &["07", "08"]),
    ("P5", &["09", "10"]),
    ("P6", &["11a", "12"]),
    ("P7", &["11b", "13a"]),
    ("P8", &["13b", "14"]),
    ("P9", &["15", "16"]),
    ("P10", &["17a", "20"]),
    ("P11", &["17b", "19"]),
    ("P12", &["22a", "22b"]),
    ("P13", &["24", "25"]),
    ("P14", &["26", "18"]),
    ("PD1", &["21"]),
    ("PD2", &["23"]),
    ("PX", &["29", "30"]),
    ("P15", &["27", "28"]),
];

/// The test tier of an evidence item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Plain `cargo test`.
    T1,
    /// Tests with `#[ignore = "tier2"]`, commands and xtask values.
    T2,
}

/// A comparison operator of an `xtask:` item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<=`
    Le,
    /// `>=`
    Ge,
    /// `<`
    Lt,
    /// `>`
    Gt,
}

/// One evidence item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// A cargo test function.
    Test {
        /// The crate directory name, for example `xtask` or `json`.
        krate: String,
        /// The test function name.
        func: String,
        /// The tier.
        tier: Tier,
    },
    /// A command that must exit 0.
    Cmd {
        /// The command line.
        argv: String,
    },
    /// A value in the JSON output of an xtask command.
    Xtask {
        /// The subcommand, for example `ci`.
        sub: String,
        /// The RFC 6901 pointer into the output.
        pointer: String,
        /// The operator.
        op: Op,
        /// The expected value as JSON text.
        value: String,
    },
    /// A checked-in record.
    Record {
        /// The record file.
        file: String,
        /// The pointer into the record.
        pointer: String,
        /// The named input of the hash, for example `tree`.
        input: String,
    },
}

impl Evidence {
    /// Gives the kind name: `test`, `cmd`, `xtask` or `record`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Test { .. } => "test",
            Self::Cmd { .. } => "cmd",
            Self::Xtask { .. } => "xtask",
            Self::Record { .. } => "record",
        }
    }

    /// Gives the tier of the item. Only `test` items can be tier 1.
    #[must_use]
    pub const fn tier(&self) -> Tier {
        match self {
            Self::Test { tier, .. } => *tier,
            _ => Tier::T2,
        }
    }
}

/// One row of an AC table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcRow {
    /// The AC ID, for example `AC-001a`.
    pub id: String,
    /// The 1-based line in the design document.
    pub line: usize,
    /// True for a row that moved to the stretch list.
    pub stretch: bool,
    /// The evidence items.
    pub evidence: Vec<Evidence>,
    /// The WPs of the Closes column, for example `["13a", "25"]`.
    pub closes: Vec<String>,
    /// The WPs of the Needs column.
    pub needs: Vec<String>,
}

/// Parses one evidence item (the text inside the backticks).
///
/// # Errors
///
/// Returns a message when the item does not match the grammar.
pub fn parse_evidence(text: &str) -> Result<Evidence, String> {
    Err(format!("no grammar for `{text}`"))
}

/// Parses every AC row of a design text.
///
/// Gives the rows and one finding for each grammar error.
#[must_use]
pub fn parse_rows(text: &str) -> (Vec<AcRow>, Vec<Finding>) {
    let _ = text;
    (Vec::new(), Vec::new())
}

/// Gives the position `(pair index, column)` of a WP in [`PAIRS`].
#[must_use]
pub fn position(wp: &str) -> Option<(usize, usize)> {
    let _ = wp;
    None
}

/// AC-018c: finds rows whose closing WP comes before a WP of the Needs column.
///
/// The closing WP is the last WP of the Closes column.
#[must_use]
pub fn needs_order(rows: &[AcRow]) -> Vec<Finding> {
    let _ = rows;
    Vec::new()
}

/// AC-018a: gives the IDs of MVP rows without an evidence item.
#[must_use]
pub fn missing(rows: &[AcRow]) -> Vec<String> {
    let _ = rows;
    Vec::new()
}

/// Runs `xtask ac [--run] [--tier2] [AC...]`.
///
/// Without `--run`, the command checks the grammar, the Needs order and missing evidence.
/// With `--run`, it also runs the evidence and writes `docs/ac-evidence.json`.
///
/// # Errors
///
/// Returns an error when the design does not read or an evidence run fails to start.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let _ = (root, args);
    Err(Error::Usage("ac".to_owned()))
}
