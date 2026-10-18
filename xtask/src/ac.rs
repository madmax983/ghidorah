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

use crate::acrun;
use crate::json::Value;
use crate::{Error, Finding};

/// The design document, relative to the workspace root.
pub const DESIGN_PATH: &str = "docs/design.md";

/// The pair order of the work packages (design Section 14.3, revision 3).
///
/// Pairs merge in this order. Inside a pair, the first WP merges first and the second WP rebases.
/// A pair with one WP has no partner.
pub const PAIRS: &[(&str, &[&str])] = &[
    ("P1", &["01", "02"]),
    ("P2", &["03", "04"]),
    ("P3", &["05", "06"]),
    ("P4", &["07", "08"]),
    ("P5", &["09", "10"]),
    ("P6", &["11a", "12"]),
    ("P7", &["11b", "18"]),
    ("P8", &["13a", "16"]),
    ("P9", &["13b", "14"]),
    ("P10", &["15", "20"]),
    ("P11", &["17a", "19"]),
    ("P12", &["17b", "21"]),
    ("P13", &["19b", "23"]),
    ("P14", &["22a", "22b"]),
    ("P15", &["24", "25"]),
    ("P16", &["19c", "25b"]),
    ("P17", &["29", "30"]),
    ("P18", &["26"]),
    ("P19", &["27", "28"]),
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
    /// True for a row that revision 3 removed.
    pub removed: bool,
    /// The evidence items.
    pub evidence: Vec<Evidence>,
    /// The WPs of the Closes column, for example `["13a", "25"]`.
    pub closes: Vec<String>,
    /// The WPs of the Needs column.
    pub needs: Vec<String>,
}

impl AcRow {
    /// Tells if the row is an MVP gate: it is not on the stretch list, and revision 3 did not remove it.
    #[must_use]
    pub const fn is_gate(&self) -> bool {
        !self.stretch && !self.removed
    }
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Tells if a test path part is a name or a template such as `fuzz_<target>`.
///
/// A template part holds `<word>` placeholders. The runner expands it over the test files.
fn is_test_part(text: &str) -> bool {
    is_name(&text.replace(['<', '>'], "")) && text.matches('<').count() == text.matches('>').count()
}

/// Tells if a test item is a template that names a family of test binaries.
#[must_use]
pub fn is_template(krate: &str, func: &str) -> bool {
    krate.contains('<') || func.contains('<')
}

fn parse_test(rest: &str) -> Result<Evidence, String> {
    let (path, tier) = rest
        .rsplit_once('@')
        .ok_or_else(|| "a test item needs `@T1` or `@T2`".to_owned())?;
    let tier = match tier {
        "T1" => Tier::T1,
        "T2" => Tier::T2,
        other => return Err(format!("unknown tier `{other}`")),
    };
    let (krate, func) = path
        .split_once("::")
        .ok_or_else(|| "a test item needs `<crate>::<fn>`".to_owned())?;
    if !is_test_part(krate) || !is_test_part(func) {
        return Err(format!("bad test path `{path}`"));
    }
    Ok(Evidence::Test {
        krate: krate.to_owned(),
        func: func.to_owned(),
        tier,
    })
}

fn parse_op(text: &str) -> Result<Op, String> {
    Ok(match text {
        "==" => Op::Eq,
        "!=" => Op::Ne,
        "<=" => Op::Le,
        ">=" => Op::Ge,
        "<" => Op::Lt,
        ">" => Op::Gt,
        other => return Err(format!("unknown operator `{other}`")),
    })
}

fn parse_xtask(rest: &str) -> Result<Evidence, String> {
    let (sub, query) = rest
        .split_once('#')
        .ok_or_else(|| "an xtask item needs `#<pointer>`".to_owned())?;
    let mut parts = query.splitn(3, ' ');
    let (Some(pointer), Some(op), Some(value)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("an xtask item needs `<pointer> <op> <value>`".to_owned());
    };
    if !is_name(sub) || !pointer.starts_with('/') || value.trim().is_empty() {
        return Err(format!("bad xtask item `{rest}`"));
    }
    Ok(Evidence::Xtask {
        sub: sub.to_owned(),
        pointer: pointer.to_owned(),
        op: parse_op(op)?,
        value: value.trim().to_owned(),
    })
}

fn parse_record(rest: &str) -> Result<Evidence, String> {
    let (file, query) = rest
        .split_once('#')
        .ok_or_else(|| "a record item needs `#<pointer>`".to_owned())?;
    let (pointer, input) = query
        .rsplit_once("@sha256=")
        .ok_or_else(|| "a record item needs `@sha256=<input>`".to_owned())?;
    if file.is_empty() || !pointer.starts_with('/') || !is_name(input) {
        return Err(format!("bad record item `{rest}`"));
    }
    Ok(Evidence::Record {
        file: file.to_owned(),
        pointer: pointer.to_owned(),
        input: input.to_owned(),
    })
}

/// Parses one evidence item (the text inside the backticks).
///
/// # Errors
///
/// Returns a message when the item does not match the grammar.
pub fn parse_evidence(text: &str) -> Result<Evidence, String> {
    let (kind, rest) = text
        .split_once(':')
        .ok_or_else(|| format!("no kind in `{text}`"))?;
    match kind {
        "test" => parse_test(rest),
        "cmd" if !rest.trim().is_empty() => Ok(Evidence::Cmd {
            argv: rest.trim().to_owned(),
        }),
        "cmd" => Err("a cmd item needs a command".to_owned()),
        "xtask" => parse_xtask(rest),
        "record" => parse_record(rest),
        other => Err(format!("unknown evidence kind `{other}`")),
    }
}

fn code_spans(cell: &str) -> Vec<&str> {
    cell.split('`').skip(1).step_by(2).collect()
}

fn wp_list(cell: &str, separator: char) -> Vec<String> {
    let cell = cell.trim();
    if cell == "-" || cell.is_empty() {
        return Vec::new();
    }
    cell.split(separator)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn is_ac_id(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("AC-") else {
        return false;
    };
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    let tail = rest.get(digits..).unwrap_or_default();
    digits == 3
        && (tail.is_empty() || (tail.len() == 1 && tail.chars().all(|c| c.is_ascii_lowercase())))
}

/// Parses every AC row of a design text.
///
/// Gives the rows and one finding for each grammar error.
#[must_use]
pub fn parse_rows(text: &str) -> (Vec<AcRow>, Vec<Finding>) {
    let mut rows = Vec::new();
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if !line.starts_with("| AC-") {
            continue;
        }
        let number = index + 1;
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let [_, id, statement, evidence, closes, needs, ..] = cells.as_slice() else {
            found.push(Finding::new(
                "AC-018a",
                DESIGN_PATH,
                number,
                "an AC row needs 5 cells",
            ));
            continue;
        };
        if !is_ac_id(id) {
            found.push(Finding::new(
                "AC-018a",
                DESIGN_PATH,
                number,
                format!("bad AC ID `{id}`"),
            ));
            continue;
        }
        let mut items = Vec::new();
        for span in code_spans(evidence) {
            match parse_evidence(span) {
                Ok(item) => items.push(item),
                Err(message) => found.push(Finding::new(
                    "AC-018a",
                    DESIGN_PATH,
                    number,
                    format!("{id}: {message}"),
                )),
            }
        }
        rows.push(AcRow {
            id: (*id).to_owned(),
            line: number,
            stretch: statement.starts_with("Moved to stretch"),
            removed: statement.starts_with("Removed in revision"),
            evidence: items,
            closes: wp_list(closes, '/'),
            needs: wp_list(needs, ','),
        });
    }
    (rows, found)
}

/// Gives the position `(pair index, column)` of a WP in [`PAIRS`].
#[must_use]
pub fn position(wp: &str) -> Option<(usize, usize)> {
    let trimmed = wp.trim();
    let wp = trimmed.strip_prefix("WP-").unwrap_or(trimmed);
    PAIRS
        .iter()
        .enumerate()
        .find_map(|(pair, (_, wps))| wps.iter().position(|w| *w == wp).map(|col| (pair, col)))
}

/// AC-018c: finds rows whose closing WP comes before a WP of the Needs column.
///
/// The closing WP is the last WP of the Closes column.
#[must_use]
pub fn needs_order(rows: &[AcRow]) -> Vec<Finding> {
    let mut found = Vec::new();
    for row in rows.iter().filter(|r| r.is_gate()) {
        let finding = |detail: String| {
            Finding::new(
                "AC-018c",
                DESIGN_PATH,
                row.line,
                format!("{}: {detail}", row.id),
            )
        };
        for wp in row.closes.iter().chain(&row.needs) {
            if position(wp).is_none() {
                found.push(finding(format!("unknown WP `{wp}`")));
            }
        }
        let Some(close) = row.closes.last().and_then(|wp| position(wp)) else {
            continue;
        };
        for need in &row.needs {
            if position(need).is_some_and(|p| p >= close) {
                let last = row.closes.last().map_or("", String::as_str);
                found.push(finding(format!(
                    "closes in WP-{last} before its Needs WP-{need}"
                )));
            }
        }
    }
    found
}

/// AC-018a: gives the IDs of MVP rows without an evidence item.
#[must_use]
pub fn missing(rows: &[AcRow]) -> Vec<String> {
    rows.iter()
        .filter(|r| r.is_gate() && r.evidence.is_empty())
        .map(|r| r.id.clone())
        .collect()
}

fn findings_json(found: &[Finding]) -> Value {
    Value::from(found.iter().map(Finding::to_json).collect::<Vec<_>>())
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
    let mut execute = false;
    let mut tier2 = false;
    let mut only = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--run" => execute = true,
            "--tier2" => tier2 = true,
            id if is_ac_id(id) => only.push(id.to_owned()),
            _ => {
                return Err(Error::Usage(
                    "cargo xtask ac [--run] [--tier2] [AC-nnn..]".to_owned(),
                ));
            }
        }
    }
    let path = root.join(DESIGN_PATH);
    let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    let (mut rows, grammar) = parse_rows(&text);
    let order = needs_order(&rows);
    let absent = missing(&rows);
    let mut ok = grammar.is_empty() && order.is_empty() && absent.is_empty();
    let mut report = vec![
        ("acs", Value::from(rows.len())),
        ("grammar", findings_json(&grammar)),
        ("order", findings_json(&order)),
        (
            "missing",
            Value::from(absent.into_iter().map(Value::from).collect::<Vec<_>>()),
        ),
    ];
    if execute {
        if !only.is_empty() {
            rows.retain(|r| only.contains(&r.id));
        }
        let outcomes = acrun::run_rows(root, &rows, tier2)?;
        ok &= outcomes.iter().all(|o| o.status != acrun::Status::Fail);
        report.push(("evidence", acrun::write_table(root, &outcomes)?));
    }
    report.push(("ok", Value::from(ok)));
    Ok(Value::object(report))
}
