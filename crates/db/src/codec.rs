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

mod edit;
mod records;
mod tables;
mod values;

#[cfg(test)]
mod tests;

use std::fmt;

use ghidorah_json::{DecodeError, DecodeKind, Fields, Value};

use crate::edit::Edit;
use crate::fact::Invalid;
use crate::notes::Notes;
use crate::program::{Program, Tables};
use crate::progress::Progress;
use crate::typesglue::{TypeInput, Types};
use crate::why::FactKey;

pub(crate) use values::Json;

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

impl CodecError {
    /// Makes an error at the current value.
    pub(crate) const fn new(reason: Reason) -> Self {
        Self {
            path: String::new(),
            reason,
        }
    }

    /// Makes an error for a text that does not have the form `form`.
    pub(crate) const fn text(form: &'static str) -> Self {
        Self::new(Reason::Text(form))
    }

    /// Makes a type error: the value has another JSON type than `expected`.
    pub(crate) const fn kind(expected: &'static str, found: &Value) -> Self {
        Self::new(Reason::Json(DecodeKind::Type {
            expected,
            found: found.kind(),
        }))
    }

    /// Puts the member name or the index `segment` in front of the path.
    #[must_use]
    pub(crate) fn at(mut self, segment: &str) -> Self {
        let mut path = String::from("/");
        for c in segment.chars() {
            match c {
                '~' => path.push_str("~0"),
                '/' => path.push_str("~1"),
                _ => path.push(c),
            }
        }
        path.push_str(&self.path);
        self.path = path;
        self
    }

    /// Puts the array index `index` in front of the path.
    #[must_use]
    pub(crate) fn at_index(self, index: usize) -> Self {
        self.at(&index.to_string())
    }
}

impl From<DecodeError> for CodecError {
    fn from(e: DecodeError) -> Self {
        Self {
            path: e.path(),
            reason: Reason::Json(e.kind()),
        }
    }
}

impl From<Invalid> for CodecError {
    fn from(i: Invalid) -> Self {
        Self::new(Reason::Invalid(i))
    }
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

/// A checked view of a JSON object: known member names only, each one time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Obj<'a> {
    value: &'a Value,
}

impl<'a> Obj<'a> {
    /// Checks that `value` is an object with members of `names` only.
    pub(crate) fn new(value: &'a Value, names: &[&str]) -> Result<Self, CodecError> {
        Fields::new(value, names)?;
        Ok(Self { value })
    }

    /// Gives the member `name`.
    pub(crate) fn member(self, name: &str) -> Result<&'a Value, CodecError> {
        self.value
            .get(name)
            .ok_or_else(|| CodecError::new(Reason::Json(DecodeKind::Missing)).at(name))
    }

    /// Reads the member `name`.
    pub(crate) fn get<T: Json>(self, name: &str) -> Result<T, CodecError> {
        T::dec(self.member(name)?).map_err(|e| e.at(name))
    }

    /// Reads the member `name` with `read`.
    pub(crate) fn with<T>(
        self,
        name: &str,
        read: impl FnOnce(&Value) -> Result<T, CodecError>,
    ) -> Result<T, CodecError> {
        read(self.member(name)?).map_err(|e| e.at(name))
    }

    /// Reads the array member `name` and decodes each item with `item`.
    pub(crate) fn each<T>(
        self,
        name: &str,
        mut item: impl FnMut(&Value) -> Result<T, CodecError>,
    ) -> Result<Vec<T>, CodecError> {
        let v = self.member(name)?;
        let items = v
            .as_array()
            .ok_or_else(|| CodecError::kind("array", v).at(name))?;
        items
            .iter()
            .enumerate()
            .map(|(i, x)| item(x).map_err(|e| e.at_index(i).at(name)))
            .collect()
    }
}

/// Gives the fact dump of a program: the input of the state hash.
///
/// The dump holds `binary` (the SHA-256 of the file), `base` and `analysis` (the tables
/// without counters), `notes` (without the ID counter) and `types` (see [`types_to_json`]).
#[must_use]
pub fn facts(program: &Program) -> Value {
    tables::facts(program)
}

/// Gives the JSON form of the types of a program: the number of types, or
/// `{ count, inputs }` when C texts added types after the prelude (design Section 9.2).
#[must_use]
pub fn types_to_json(types: &Types) -> Value {
    let count = Value::from(types.store().len());
    if types.inputs().is_empty() {
        return count;
    }
    let inputs = types.inputs().iter().map(Json::enc).collect();
    Value::object([("count", count), ("inputs", Value::Array(inputs))])
}

/// Reads the JSON form of [`types_to_json`]: the number of types and the inputs.
///
/// # Errors
///
/// Returns a [`CodecError`] for another shape.
pub fn types_from_json(value: &Value) -> Result<(u64, Vec<TypeInput>), CodecError> {
    if value.as_object().is_some() {
        let o = Obj::new(value, &["count", "inputs"])?;
        return Ok((o.get("count")?, o.each("inputs", TypeInput::dec)?));
    }
    Ok((u64::dec(value)?, Vec::new()))
}

/// Gives the JSON form of the tables of one layer, with the counter of new why-records.
#[must_use]
pub fn tables_to_json(tables: &Tables) -> Value {
    tables::encode(tables, true)
}

/// Reads the tables of one layer.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape, a bad text or a broken table rule.
pub fn tables_from_json(value: &Value) -> Result<Tables, CodecError> {
    tables::decode(value)
}

/// Gives the JSON form of the note store, with the counter of new note IDs.
#[must_use]
pub fn notes_to_json(notes: &Notes) -> Value {
    tables::encode_notes(notes)
}

/// Reads a note store.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape, a bad text or a broken note rule.
pub fn notes_from_json(value: &Value) -> Result<Notes, CodecError> {
    tables::decode_notes(value)
}

/// Gives the JSON form of the progress rows and the marks.
#[must_use]
pub fn progress_to_json(progress: &Progress) -> Value {
    tables::encode_progress(progress)
}

/// Reads progress rows and marks.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape or a bad text.
pub fn progress_from_json(value: &Value) -> Result<Progress, CodecError> {
    tables::decode_progress(value)
}

/// Gives the JSON form of an edit.
#[must_use]
pub fn edit_to_json(edit: &Edit) -> Value {
    edit::encode(edit)
}

/// Reads an edit.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape, a bad text or a broken table rule.
pub fn edit_from_json(value: &Value) -> Result<Edit, CodecError> {
    edit::decode(value)
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
    key.enc()
}

/// Reads a fact key.
///
/// # Errors
///
/// Returns a [`CodecError`] for a bad shape or a bad text.
pub fn key_from_json(value: &Value) -> Result<FactKey, CodecError> {
    FactKey::dec(value)
}
