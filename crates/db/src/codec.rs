//! The JSON codec of every table and every edit (design Sections 3.7, 3.10 and 3.12).
//!
//! The journal, the snapshot and the state hash use these forms. Each decoder reads its
//! encoder output back to an equal value. A decoder refuses an unknown member, a missing
//! member, a bad text form and a value that breaks a table rule.
//!
//! | Value | JSON form |
//! |---|---|
//! | address, RAM offset | `"0x401000"`, `"ext:0x3"` |
//! | range | `{"first":"0x10","last":"0x1f"}` |
//! | fact | `{"value":..,"source":"agent","tx":42,"session":"mcp-1","force":false}` |
//! | empty slot | `null` |
//! | type | its index in the type store, for example `7` |
//! | function ID | its entry address |
//! | variable ID | its text form, for example `"var:0x401130/stack:-0x14"` |
//! | reference key | `{"from":..,"op_index":-1,"to":..,"kind":"read"}` |
//! | fact key | `{"k":"symbol","addr":..,"key":0}` and the other forms of [`key_to_json`] |
//! | edit | `{"op":"SetName",..}` with the fields of its variant |
//! | tables | `{"comments":[..],"data":[..],"funcs":[..],..}` with one array per table |
//!
//! [`facts`] gives the fact dump of a program for the state hash and the snapshot.

#[cfg(test)]
mod tests;

use std::fmt;

use ghidorah_json::{DecodeKind, Value};

use crate::edit::Edit;
use crate::fact::Invalid;
use crate::notes::Notes;
use crate::program::{Program, Tables};
use crate::progress::Progress;
use crate::why::FactKey;

/// The reason of a [`CodecError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// The JSON shape is wrong: a type, a range, a missing or unknown member.
    Json(DecodeKind),
    /// A text does not have its form. The value names the form, for example `address`.
    Text(&'static str),
    /// The value breaks a rule of its table.
    Invalid(Invalid),
}

/// A decode error with the RFC 6901 pointer of the bad part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError {
    /// The pointer of the bad part, for example `/name/value`.
    pub path: String,
    /// The reason.
    pub reason: Reason,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            Reason::Json(kind) => write!(f, "{} at '{}'", kind.as_str(), self.path),
            Reason::Text(form) => write!(f, "The text at '{}' is not a {form}.", self.path),
            Reason::Invalid(i) => write!(f, "The value at '{}' is not valid: {i}", self.path),
        }
    }
}

impl std::error::Error for CodecError {}

/// Gives the fact dump of a program: the input of the state hash.
///
/// The dump holds `binary` (the SHA-256 of the file), `base` and `analysis` (the tables
/// without counters), `notes` (without the ID counter) and `types` (the number of types).
#[must_use]
pub fn facts(program: &Program) -> Value {
    let _ = program;
    Value::Null
}

/// Gives the JSON form of the tables of one layer, with the counter of new why-records.
#[must_use]
pub fn tables_to_json(tables: &Tables) -> Value {
    let _ = tables;
    Value::Null
}

/// Reads the tables of one layer.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape, a bad text or a broken table rule.
pub fn tables_from_json(value: &Value) -> Result<Tables, CodecError> {
    let _ = value;
    Err(text_error("tables"))
}

/// Gives the JSON form of the note store, with the counter of new note IDs.
#[must_use]
pub fn notes_to_json(notes: &Notes) -> Value {
    let _ = notes;
    Value::Null
}

/// Reads a note store.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape, a bad text or a broken note rule.
pub fn notes_from_json(value: &Value) -> Result<Notes, CodecError> {
    let _ = value;
    Err(text_error("notes"))
}

/// Gives the JSON form of the progress rows and the marks.
#[must_use]
pub fn progress_to_json(progress: &Progress) -> Value {
    let _ = progress;
    Value::Null
}

/// Reads progress rows and marks.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape or a bad text.
pub fn progress_from_json(value: &Value) -> Result<Progress, CodecError> {
    let _ = value;
    Err(text_error("progress"))
}

/// Gives the JSON form of an edit.
#[must_use]
pub fn edit_to_json(edit: &Edit) -> Value {
    let _ = edit;
    Value::Null
}

/// Reads an edit.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape, a bad text or a broken table rule.
pub fn edit_from_json(value: &Value) -> Result<Edit, CodecError> {
    let _ = value;
    Err(text_error("edit"))
}

/// Gives the JSON form of a fact key.
///
/// | Key | Form |
/// |---|---|
/// | `CodeUnit`, `Data`, `Entry`, `Reloc`, `Fde` | `{"k":"code_unit","at":"0x10"}` |
/// | `Symbol` | `{"k":"symbol","addr":..,"key":0}` |
/// | `Func`, `Signature`, `Noreturn` | `{"k":"func","func":"0x10"}` |
/// | `Ref` | `{"k":"ref","ref":{"from":..,"op_index":-1,"to":..,"kind":"read"}}` |
/// | `Comment` | `{"k":"comment","addr":..,"kind":"eol"}` |
/// | `JumpTable`, `FlowOverride`, `Str` | `{"k":"jump_table","at":..}` |
/// | `Var` | `{"k":"var","var":"var:0x10/ret"}` |
/// | `Import`, `Export` | `{"k":"import","id":"imp:puts"}` |
/// | `Note` | `{"k":"note","note":7}` |
#[must_use]
pub fn key_to_json(key: &FactKey) -> Value {
    let _ = key;
    Value::Null
}

/// Reads a fact key.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape or a bad text.
pub fn key_from_json(value: &Value) -> Result<FactKey, CodecError> {
    let _ = value;
    Err(text_error("fact key"))
}

/// Makes an error for a text that does not have the form `form`, at the root.
const fn text_error(form: &'static str) -> CodecError {
    CodecError {
        path: String::new(),
        reason: Reason::Text(form),
    }
}
