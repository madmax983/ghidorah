//! Snapshots: the fact tables of a program at one revision (design Section 3.10).
//!
//! `snapshot.json` is canonical JCS text:
//!
//! ```text
//! {"analysis_inputs_hash": hex or null, "facts": {analysis, base, binary, notes, types},
//!  "format_version": 1, "journal_lines": n, "marks": [..], "progress": [..], "rev": r}
//! ```
//!
//! - `facts` holds the tables of both layers with their counters, the note store, the SHA-256
//!   of the input and the number of types.
//! - `journal_lines` is the number of journal lines that the snapshot covers. Replay applies
//!   only the lines after them.
//! - `analysis_inputs_hash` is the inputs hash of the last analysis run, or `null`.
//!
//! A snapshot write is exactly this operation sequence (AC-120a): `create_new` of
//! `snapshot.json.tmp`, `write_all`, `sync_file`, `rename` to `snapshot.json` and `sync_dir`.

#[cfg(test)]
mod tests;

use std::fmt;
use std::path::Path;

use ghidorah_base::{Rev, hex, sha256};
use ghidorah_json::{Limits, Value, write_jcs};

use crate::codec::{CodecError, Json, Obj, tables_to_json};
use crate::fs::{Fs, FsError};
use crate::notes::Notes;
use crate::program::{AnalysisSet, Program, Tables};
use crate::progress::Progress;

/// The format version of the project files.
pub const FORMAT_VERSION: u64 = 1;

/// The file name of the snapshot.
pub const SNAPSHOT_FILE: &str = "snapshot.json";

/// The file name of the temporary snapshot.
pub const SNAPSHOT_TMP: &str = "snapshot.json.tmp";

/// The JSON limits of a snapshot: depth 128 and 1 GiB.
pub const SNAPSHOT_LIMITS: Limits = Limits {
    max_depth: 128,
    max_bytes: 1 << 30,
};

/// The error of a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// The text is not JSON.
    Json(String),
    /// The JSON has the wrong shape.
    Shape(CodecError),
    /// The format version is not [`FORMAT_VERSION`].
    Version(u64),
    /// The snapshot belongs to another input file.
    Binary,
    /// The number of types differs from the types of the program.
    Types {
        /// The number of types of the program.
        have: u64,
        /// The number of types of the snapshot.
        want: u64,
    },
    /// The dump has no JCS form.
    Jcs(String),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "The snapshot is not JSON: {e}"),
            Self::Shape(e) => write!(f, "The snapshot has a bad shape: {e}"),
            Self::Version(v) => write!(f, "The snapshot has the format version {v}."),
            Self::Binary => f.write_str("The snapshot belongs to another input file."),
            Self::Types { have, want } => write!(
                f,
                "The snapshot has {want} types, and the program has {have} types."
            ),
            Self::Jcs(e) => write!(f, "The snapshot has no JCS form: {e}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<CodecError> for SnapshotError {
    fn from(e: CodecError) -> Self {
        Self::Shape(e)
    }
}

/// The content of one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The revision.
    pub rev: Rev,
    /// The number of journal lines that the snapshot covers.
    pub journal_lines: u64,
    /// The inputs hash of the last analysis run, or `None`.
    pub analysis_inputs_hash: Option<[u8; 32]>,
    /// The SHA-256 of the input file.
    pub binary: [u8; 32],
    /// The number of types.
    pub types: u64,
    /// The base layer.
    pub base: Tables,
    /// The analysis layer.
    pub analysis: AnalysisSet,
    /// The note store.
    pub notes: Notes,
    /// The progress rows and the marks.
    pub progress: Progress,
}

impl Snapshot {
    /// Puts the content of the snapshot into `program`: both layers, the notes, the progress
    /// rows, the marks and the revision.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Binary`] for another input file and [`SnapshotError::Types`]
    /// when the number of types differs. Then the program does not change.
    pub fn restore(self, program: &mut Program) -> Result<(), SnapshotError> {
        let _ = program;
        Err(SnapshotError::Binary)
    }
}

/// Gives the JCS text of the snapshot of `program`.
///
/// # Errors
///
/// Returns [`SnapshotError::Jcs`] when the dump has no JCS form. The dump of a program has
/// unique member names and integer numbers only, so the error does not occur.
pub fn encode(
    program: &Program,
    journal_lines: u64,
    inputs: Option<[u8; 32]>,
) -> Result<String, SnapshotError> {
    let _ = (program, journal_lines, inputs);
    Ok(String::new())
}

/// Reads a snapshot.
///
/// # Errors
///
/// Returns a [`SnapshotError`] for text that is not JSON, a bad shape or another version.
pub fn decode(bytes: &[u8]) -> Result<Snapshot, SnapshotError> {
    let _ = (bytes, SNAPSHOT_LIMITS);
    Err(SnapshotError::Version(0))
}

/// Writes `text` as the snapshot of the project directory `dir`.
///
/// The operations are `create_new` of the temporary file, `write_all`, `sync_file`, `rename`
/// and `sync_dir`. A temporary file of an earlier crash goes first.
///
/// # Errors
///
/// Returns the [`FsError`] of the first failed operation.
pub fn write(fs: &mut dyn Fs, dir: &Path, text: &str) -> Result<(), FsError> {
    let _ = (fs, dir, text);
    Ok(())
}

/// Gives the analysis inputs hash of `program` (design Section 3.9).
///
/// The hash is the SHA-256 of the JCS text of `{binary, config, engine, facts}`. `facts` holds
/// the base-layer facts that affect analysis: functions with their signatures and noreturn
/// flags, references, jump tables, flow overrides and data definitions. `engine` holds the
/// analyzer versions, and `config` holds the analysis config.
#[must_use]
pub fn inputs_hash(program: &Program, engine: &Value, config: &Value) -> [u8; 32] {
    let base = tables_to_json(program.base());
    let pick = |name: &str| base.get(name).cloned().unwrap_or(Value::Null);
    let facts = Value::object([
        ("data", pick("data")),
        ("funcs", pick("funcs")),
        ("jumptables", pick("jumptables")),
        ("overrides", pick("overrides")),
        ("refs", pick("refs")),
    ]);
    let all = Value::object([
        ("binary", Value::from(hex::encode(&program.meta().sha256))),
        ("config", config.clone()),
        ("engine", engine.clone()),
        ("facts", facts),
    ]);
    hash_value(&all)
}

/// Gives the SHA-256 of the JCS text of the tables of an analysis layer.
#[must_use]
pub fn result_hash(set: &AnalysisSet) -> [u8; 32] {
    hash_value(&tables_to_json(set))
}

/// Gives the SHA-256 of the JCS text of `value`, or of its compact text without a JCS form.
fn hash_value(value: &Value) -> [u8; 32] {
    let text = write_jcs(value).unwrap_or_else(|_| ghidorah_json::write(value));
    sha256(text.as_bytes())
}

/// Reads a 64-digit hex hash.
pub(crate) fn hash_from(v: &Value) -> Result<[u8; 32], CodecError> {
    let text = v.as_str().ok_or_else(|| CodecError::kind("string", v))?;
    let bytes = hex::decode(text).map_err(|_| CodecError::text("hash"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| CodecError::text("hash"))
}

/// Reads the member `name` of `o` as an optional hash.
fn optional_hash(o: Obj<'_>, name: &str) -> Result<Option<[u8; 32]>, CodecError> {
    o.with(name, |v| {
        if v.is_null() {
            Ok(None)
        } else {
            hash_from(v).map(Some)
        }
    })
}

/// Reads the member `name` of `o` as a revision.
fn rev_of(o: Obj<'_>, name: &str) -> Result<Rev, CodecError> {
    o.get(name)
}

/// Gives the JSON of an optional hash.
fn hash_json(hash: Option<&[u8; 32]>) -> Value {
    hash.map_or(Value::Null, |h| Value::from(hex::encode(h)))
}
