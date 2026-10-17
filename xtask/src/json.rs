//! Small strict JSON value, parser and writer for xtask.
//!
//! The xtask crate reads `cargo metadata`, `cargo --message-format=json` and `llvm-cov` output.
//! Objects keep their keys in sorted order, so the writer output is deterministic.

use std::collections::BTreeMap;
use std::fmt;

/// The maximum nesting depth that [`parse`] accepts.
pub const MAX_DEPTH: usize = 128;

/// One JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// The `null` literal.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number in its source text form.
    Number(String),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Self>),
    /// An object with sorted keys.
    Object(BTreeMap<String, Self>),
}

/// A parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The byte offset of the failure.
    pub offset: usize,
    /// What is wrong.
    pub message: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for ParseError {}

/// Parses one JSON text (RFC 8259).
///
/// # Errors
///
/// Returns a [`ParseError`] for bad syntax, a duplicate key, trailing data or nesting above [`MAX_DEPTH`].
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let _ = text;
    Err(ParseError {
        offset: 0,
        message: "parser missing",
    })
}

/// Writes a value as compact JSON text.
#[must_use]
pub fn write(value: &Value) -> String {
    let _ = value;
    String::new()
}

impl Value {
    /// Makes an object from key and value pairs.
    pub fn object<K: Into<String>>(items: impl IntoIterator<Item = (K, Self)>) -> Self {
        Self::Object(items.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Gives the member `key` of an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        let _ = key;
        None
    }

    /// Resolves an RFC 6901 pointer.
    #[must_use]
    pub fn pointer(&self, pointer: &str) -> Option<&Self> {
        let _ = pointer;
        None
    }

    /// Gives the text of a string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        None
    }

    /// Gives the value of a boolean.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        None
    }

    /// Gives a number as `u64` when it is a non-negative integer that fits.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        None
    }

    /// Gives a number as `f64`.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        None
    }

    /// Gives the items of an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        None
    }

    /// Gives the members of an object.
    #[must_use]
    pub const fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        None
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&write(self))
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::String(text.to_owned())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Self::String(text)
    }
}

impl From<bool> for Value {
    fn from(flag: bool) -> Self {
        Self::Bool(flag)
    }
}

impl From<u64> for Value {
    fn from(number: u64) -> Self {
        Self::Number(number.to_string())
    }
}

impl From<usize> for Value {
    fn from(number: usize) -> Self {
        Self::Number(number.to_string())
    }
}

impl From<Vec<Self>> for Value {
    fn from(items: Vec<Self>) -> Self {
        Self::Array(items)
    }
}
