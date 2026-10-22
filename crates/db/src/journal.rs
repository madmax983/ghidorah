//! The journal: one checksummed JSON line per commit (design Sections 3.7 and 3.10).
//!
//! The journal file `journal.jsonl` only grows. Each line is one JSON object with `"v":2`
//! and a checksum member `crc` at the end. `crc` is the first 16 hex digits of the SHA-256
//! of the line text without the `crc` member.
//!
//! | Line | Members after `v` |
//! |---|---|
//! | commit | `rev`, `tx`, `label`, `source`, `session`, `force`, `types` (only when a C text added types), `edits`, `undo_of`, `redo_of` |
//! | analysis run | `rev`, `tx`, `op: "AnalysisRun"`, `state`, `inputs_hash`, `fuel_used`, `result_hash` |
//! | meta | see [`crate::meta`] |
//!
//! An edit item of a commit line is `{"op":"SetName","new":<edit>,"old":<inverse>}`. An item
//! of an undo or a redo commit also has `of`: the transaction that the item reverts or applies
//! again. An analysis run line takes the place of thousands of analysis facts. The snapshot
//! holds those facts.
//!
//! [`parse`] reads a journal file:
//!
//! | Input | Result |
//! |---|---|
//! | each line ends with a line end and decodes | all lines |
//! | the text after the last line end is not empty | the lines before it, and `torn: true` |
//! | a line with a line end does not decode | [`JournalError::Corrupt`] with its line number |
//!
//! A line with `"v":1` also decodes. Its edits get the new `ext:` addresses of a map (the
//! [`crate::migrate`] module).

#[cfg(test)]
mod tests;

use std::fmt;

use ghidorah_base::{Rev, TxId, hex, sha256};
use ghidorah_json::{DecodeKind, Limits, Object, Value};

use crate::codec::{CodecError, Json, Obj, Reason, edit_from_json, edit_to_json};
use crate::edit::EditKind;
use crate::fact::SessionLabel;
use crate::meta::{META_KEY, MetaLine};
use crate::migrate::ExtMap;
use crate::snapshot::hash_from;
use crate::source::Source;
use crate::tx::{Applied, Commit, TxLabel};
use crate::typesglue::TypeInput;

/// The version member `v` of each line.
pub const VERSION: u64 = 2;

/// The oldest version of a line that [`decode`] reads.
pub const MIN_VERSION: u64 = 1;

/// The file name of the journal in a project directory.
pub const JOURNAL_FILE: &str = "journal.jsonl";

/// The `op` value of an analysis run line.
pub const RUN_OP: &str = "AnalysisRun";

/// The longest line in bytes.
pub const MAX_LINE_BYTES: usize = 64 * 1024 * 1024;

/// The JSON limits of one line.
const LINE_LIMITS: Limits = Limits {
    max_depth: 128,
    max_bytes: MAX_LINE_BYTES,
};

/// The member names of a commit line.
const TX_MEMBERS: [&str; 12] = [
    "v", "rev", "tx", "label", "source", "session", "force", "types", "edits", "undo_of",
    "redo_of", "crc",
];

/// The member names of an analysis run line.
const RUN_MEMBERS: [&str; 9] = [
    "v",
    "rev",
    "tx",
    "op",
    "state",
    "inputs_hash",
    "fuel_used",
    "result_hash",
    "crc",
];

/// One committed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxLine {
    /// The revision after the commit.
    pub rev: Rev,
    /// The transaction ID.
    pub tx: TxId,
    /// The label.
    pub label: TxLabel,
    /// The source.
    pub source: Source,
    /// The session label.
    pub session: SessionLabel,
    /// An edit of the transaction used `force: true`.
    pub force: bool,
    /// The C texts that added types to the store before the edits, in parse order.
    pub types: Vec<TypeInput>,
    /// The applied edits with their exact inverses, in apply order.
    pub edits: Vec<Applied>,
    /// For each edit of an undo or a redo commit: the transaction that it reverts or applies
    /// again. An original commit has an empty list.
    pub of: Vec<TxId>,
    /// The transactions that the commit reverts.
    pub undo_of: Vec<TxId>,
    /// The transactions that the commit applies again.
    pub redo_of: Vec<TxId>,
}

impl TxLine {
    /// Gives the line of an original commit: no `undo_of`, no `redo_of`.
    #[must_use]
    pub fn of_commit(commit: &Commit) -> Self {
        Self {
            rev: commit.rev,
            tx: commit.tx,
            label: commit.label.clone(),
            source: commit.source,
            session: commit.session.clone(),
            force: commit.force,
            types: commit.types.clone(),
            edits: commit.edits.clone(),
            of: Vec::new(),
            undo_of: Vec::new(),
            redo_of: Vec::new(),
        }
    }

    /// Tells if the commit is an original transaction: not an undo and not a redo.
    #[must_use]
    pub const fn is_original(&self) -> bool {
        self.undo_of.is_empty() && self.redo_of.is_empty()
    }
}

/// The state of an analysis run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RunState {
    /// The run is complete.
    Complete,
    /// The run stopped on its fuel budget.
    BudgetStopped,
}

impl RunState {
    /// Gives the name: `complete` or `budget_stopped`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::BudgetStopped => "budget_stopped",
        }
    }

    /// Gives the state of a name, or `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Complete, Self::BudgetStopped]
            .into_iter()
            .find(|s| s.name() == name)
    }
}

/// The marker of one analysis run that changed the analysis layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunLine {
    /// The revision after the commit.
    pub rev: Rev,
    /// The transaction ID.
    pub tx: TxId,
    /// The state after the run.
    pub state: RunState,
    /// The analysis inputs hash of the run (design Section 3.9).
    pub inputs_hash: [u8; 32],
    /// The fuel that the run used.
    pub fuel_used: u64,
    /// The SHA-256 of the JCS text of the new analysis layer.
    pub result_hash: [u8; 32],
}

/// One journal line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A committed transaction.
    Tx(Box<TxLine>),
    /// An analysis run marker.
    Run(RunLine),
    /// Session metadata.
    Meta(MetaLine),
}

impl Line {
    /// Gives the revision of a commit or a run line. A meta line gives `None`.
    #[must_use]
    pub fn rev(&self) -> Option<Rev> {
        match self {
            Self::Tx(t) => Some(t.rev),
            Self::Run(r) => Some(r.rev),
            Self::Meta(_) => None,
        }
    }

    /// Gives the transaction ID of a commit or a run line. A meta line gives `None`.
    #[must_use]
    pub fn tx(&self) -> Option<TxId> {
        match self {
            Self::Tx(t) => Some(t.tx),
            Self::Run(r) => Some(r.tx),
            Self::Meta(_) => None,
        }
    }
}

/// The error of one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineError {
    /// The line has no checksum, or the checksum does not match.
    Crc,
    /// The line is not JSON text.
    Json(String),
    /// The JSON has the wrong shape.
    Shape(CodecError),
    /// The version member is not in [`MIN_VERSION`] to [`VERSION`].
    Version(u64),
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crc => f.write_str("The line checksum does not match."),
            Self::Json(e) => write!(f, "The line is not JSON: {e}"),
            Self::Shape(e) => write!(f, "The line has a bad shape: {e}"),
            Self::Version(v) => write!(
                f,
                "The line has the version {v}, not {MIN_VERSION} to {VERSION}."
            ),
        }
    }
}

impl std::error::Error for LineError {}

impl From<CodecError> for LineError {
    fn from(e: CodecError) -> Self {
        Self::Shape(e)
    }
}

/// The error of a journal file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// A line with a line end does not decode: `JOURNAL_CORRUPT`.
    Corrupt {
        /// The line number, from 1.
        line: usize,
        /// The reason.
        reason: LineError,
    },
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt { line, reason } => write!(f, "The journal line {line} is bad: {reason}"),
        }
    }
}

impl std::error::Error for JournalError {}

/// The lines of a journal file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Journal {
    /// The lines that end with a line end, in file order.
    pub lines: Vec<Line>,
    /// The byte length of the complete lines.
    pub valid_len: usize,
    /// The file has text after its last line end: a torn last line.
    pub torn: bool,
}

/// Gives the checksum of a line text without its `crc` member: 16 hex digits.
#[must_use]
pub fn crc(body: &str) -> String {
    let digest = sha256(body.as_bytes());
    hex::encode(digest.get(..8).unwrap_or(&digest))
}

/// Gives the JSON object of the members of a line, without `crc`.
fn body(line: &Line) -> Value {
    let mut out = Object::new();
    out.push("v", Value::from(VERSION));
    match line {
        Line::Tx(t) => {
            out.push("rev", t.rev.enc());
            out.push("tx", t.tx.enc());
            out.push("label", Value::from(t.label.as_str()));
            out.push("source", t.source.enc());
            out.push("session", t.session.enc());
            out.push("force", t.force.enc());
            if !t.types.is_empty() {
                out.push(
                    "types",
                    Value::Array(t.types.iter().map(Json::enc).collect()),
                );
            }
            let edits = t
                .edits
                .iter()
                .enumerate()
                .map(|(i, a)| edit_item(a, t.of.get(i).copied()))
                .collect();
            out.push("edits", Value::Array(edits));
            out.push("undo_of", tx_list(&t.undo_of));
            out.push("redo_of", tx_list(&t.redo_of));
        }
        Line::Run(r) => {
            out.push("rev", r.rev.enc());
            out.push("tx", r.tx.enc());
            out.push("op", Value::from(RUN_OP));
            out.push("state", Value::from(r.state.name()));
            out.push("inputs_hash", Value::from(hex::encode(&r.inputs_hash)));
            out.push("fuel_used", Value::from(r.fuel_used));
            out.push("result_hash", Value::from(hex::encode(&r.result_hash)));
        }
        Line::Meta(m) => {
            for (k, v) in m.members() {
                out.push(k, v);
            }
        }
    }
    Value::Object(out)
}

/// Gives one edit item: `{op, new, old, of?}`.
fn edit_item(a: &Applied, of: Option<TxId>) -> Value {
    let mut item = Object::new();
    item.push("op", Value::from(a.edit.kind().name()));
    item.push("new", edit_to_json(&a.edit));
    item.push("old", edit_to_json(&a.inverse));
    if let Some(tx) = of {
        item.push("of", tx.enc());
    }
    Value::Object(item)
}

/// Gives `null` for an empty list, else the array of the IDs.
fn tx_list(list: &[TxId]) -> Value {
    if list.is_empty() {
        Value::Null
    } else {
        Value::Array(list.iter().map(Json::enc).collect())
    }
}

/// Gives the text of one line with its checksum, without a line end.
#[must_use]
pub fn encode(line: &Line) -> String {
    let text = ghidorah_json::write(&body(line));
    let sum = crc(&text);
    let open = text.strip_suffix('}').unwrap_or(&text);
    format!("{open},\"crc\":\"{sum}\"}}")
}

/// Gives the line text without its `crc` member when the checksum matches, else `None`.
fn checked_body(text: &str) -> Option<String> {
    const KEY: &str = ",\"crc\":\"";
    let at = text.rfind(KEY)?;
    let tail = text.get(at..)?;
    let sum = tail.get(KEY.len()..KEY.len().checked_add(16)?)?;
    if tail.get(KEY.len().checked_add(16)?..) != Some("\"}") {
        return None;
    }
    let body = format!("{}}}", text.get(..at)?);
    (crc(&body) == sum).then_some(body)
}

/// Reads one line text without its line end. The edits of a version 1 line get the new
/// `ext:` addresses of `v1`.
///
/// # Errors
///
/// Returns [`LineError::Crc`] for a missing or wrong checksum, [`LineError::Json`] for text
/// that is not JSON, [`LineError::Version`] for another version and [`LineError::Shape`] for a
/// bad member.
pub fn decode(text: &str, v1: &ExtMap) -> Result<Line, LineError> {
    checked_body(text).ok_or(LineError::Crc)?;
    let mut value =
        ghidorah_json::parse(text, &LINE_LIMITS).map_err(|e| LineError::Json(e.to_string()))?;
    match value.get("v").map(Value::as_u64) {
        Some(Some(1)) => {
            if let Value::Object(o) = &mut value
                && let Some(edits) = o.get_mut("edits")
            {
                *edits = v1.remap(std::mem::take(edits));
            }
        }
        Some(Some(VERSION)) => {}
        Some(Some(v)) => return Err(LineError::Version(v)),
        Some(None) => return Err(LineError::Shape(CodecError::text("version").at("v"))),
        None => {
            let missing = CodecError::new(Reason::Json(DecodeKind::Missing)).at("v");
            return Err(LineError::Shape(missing));
        }
    }
    if value.get(META_KEY).is_some() {
        return Ok(Line::Meta(MetaLine::from_json(&value)?));
    }
    if value.get("op").and_then(Value::as_str) == Some(RUN_OP) {
        return Ok(Line::Run(read_run(&value)?));
    }
    Ok(Line::Tx(Box::new(read_tx(&value)?)))
}

/// Reads a journal file. The edits of a version 1 line get the new `ext:` addresses of `v1`.
///
/// # Errors
///
/// Returns [`JournalError::Corrupt`] with the line number of the first line that ends with a
/// line end and does not decode.
pub fn parse(bytes: &[u8], v1: &ExtMap) -> Result<Journal, JournalError> {
    let mut out = Journal::default();
    let mut start = 0usize;
    let mut number = 0usize;
    // Each pass moves `start` past one line end, so the loop ends.
    while let Some(rest) = bytes.get(start..).filter(|r| !r.is_empty()) {
        let Some(end) = rest.iter().position(|b| *b == b'\n') else {
            out.torn = true;
            break;
        };
        number = number.saturating_add(1);
        let corrupt = |reason| JournalError::Corrupt {
            line: number,
            reason,
        };
        let line = rest.get(..end).unwrap_or_default();
        let text = std::str::from_utf8(line)
            .map_err(|_| corrupt(LineError::Json("the line is not UTF-8".to_owned())))?;
        out.lines.push(decode(text, v1).map_err(corrupt)?);
        start = start.saturating_add(end).saturating_add(1);
        out.valid_len = start;
    }
    Ok(out)
}

/// Reads a list of transaction IDs: `null` or an array.
fn tx_ids(o: Obj<'_>, name: &str) -> Result<Vec<TxId>, CodecError> {
    o.with(name, |v| {
        if v.is_null() {
            return Ok(Vec::new());
        }
        let items = v.as_array().ok_or_else(|| CodecError::kind("array", v))?;
        items
            .iter()
            .enumerate()
            .map(|(i, x)| TxId::dec(x).map_err(|e| e.at_index(i)))
            .collect()
    })
}

/// Reads a commit line.
fn read_tx(value: &Value) -> Result<TxLine, CodecError> {
    let o = Obj::new(value, &TX_MEMBERS)?;
    let label = o.with("label", |v| {
        v.as_str()
            .and_then(|t| TxLabel::new(t).ok())
            .ok_or_else(|| CodecError::text("transaction label"))
    })?;
    let types = if value.get("types").is_some() {
        o.each("types", TypeInput::dec)?
    } else {
        Vec::new()
    };
    let mut edits = Vec::new();
    let mut of = Vec::new();
    for (applied, item_of) in o.each("edits", read_item)? {
        edits.push(applied);
        of.extend(item_of);
    }
    let undo_of = tx_ids(o, "undo_of")?;
    let redo_of = tx_ids(o, "redo_of")?;
    let original = undo_of.is_empty() && redo_of.is_empty();
    if (original && !of.is_empty()) || (!original && of.len() != edits.len()) {
        return Err(CodecError::text("list of the of members").at("edits"));
    }
    Ok(TxLine {
        rev: o.get("rev")?,
        tx: o.get("tx")?,
        label,
        source: o.get("source")?,
        session: o.get("session")?,
        force: o.get("force")?,
        types,
        edits,
        of,
        undo_of,
        redo_of,
    })
}

/// Reads an analysis run line.
fn read_run(value: &Value) -> Result<RunLine, CodecError> {
    let o = Obj::new(value, &RUN_MEMBERS)?;
    let state = o.with("state", |v| {
        v.as_str()
            .and_then(RunState::parse)
            .ok_or_else(|| CodecError::text("run state"))
    })?;
    Ok(RunLine {
        rev: o.get("rev")?,
        tx: o.get("tx")?,
        state,
        inputs_hash: o.with("inputs_hash", hash_from)?,
        fuel_used: o.get("fuel_used")?,
        result_hash: o.with("result_hash", hash_from)?,
    })
}

/// Reads an edit item of a commit line. Gives the applied edit and its `of` member.
fn read_item(value: &Value) -> Result<(Applied, Option<TxId>), CodecError> {
    let o = Obj::new(value, &["op", "new", "old", "of"])?;
    let edit = o.with("new", edit_from_json)?;
    let inverse = o.with("old", edit_from_json)?;
    let op = o.with("op", |v| {
        v.as_str()
            .and_then(EditKind::parse)
            .ok_or_else(|| CodecError::text("edit kind"))
    })?;
    if op != edit.kind() {
        return Err(CodecError::text("edit kind of new").at("op"));
    }
    let of = match value.get("of") {
        Some(v) => Some(TxId::dec(v).map_err(|e| e.at("of"))?),
        None => None,
    };
    Ok((Applied { edit, inverse }, of))
}
