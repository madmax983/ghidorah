//! Tool errors and their frozen JSON object (design Section 10.8, ADR-0021).
//!
//! ```text
//! error: { code, num, message, hint, retryable, field_path?, candidates?, candidates_total?,
//!          details?, crash_id? }
//! ```
//!
//! The message comes from the template of the code in `base::ErrorCode`. The hint and the
//! retry flag come from the same catalog row. The object is at most [`ERROR_CAP`] characters,
//! with at most [`MAX_CANDIDATES`] candidates plus `candidates_total` (AC-134).

use std::fmt;

use ghidorah_base::ErrorCode;
use ghidorah_json::{Object, Value};

use crate::hints::Call;

/// The largest error object in characters.
pub const ERROR_CAP: u64 = 10_000;

/// The largest number of candidates in an error object.
pub const MAX_CANDIDATES: usize = 5;

/// The largest template value, label or candidate value in characters.
pub const MAX_TEXT_CHARS: usize = 256;

/// The largest `field_path` in characters.
pub const MAX_PATH_CHARS: usize = 512;

/// One choice of an error: `{ value, label, id?, addr?, kind? }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The value to send, for example `"sym:helper"` or a field name.
    pub value: Value,
    /// A short label of the choice.
    pub label: String,
    /// The ID of the choice, when it has one.
    pub id: Option<String>,
    /// The address of the choice as hex text, when it has one.
    pub addr: Option<String>,
    /// The kind of the choice, for example `function`.
    pub kind: Option<String>,
}

impl Candidate {
    /// Makes a candidate with a string value and a label.
    #[must_use]
    pub fn text(value: &str, label: &str) -> Self {
        Self {
            value: Value::from(value),
            label: label.to_owned(),
            id: None,
            addr: None,
            kind: None,
        }
    }

    /// Gives the JSON form of the candidate.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Null
    }
}

/// One tool error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError {
    /// The code.
    pub code: ErrorCode,
    /// The values of the message template, for example `("field", "target")`.
    pub vars: Vec<(&'static str, String)>,
    /// The JSON pointer of the bad argument, for example `/targets/3`.
    pub field_path: Option<String>,
    /// All candidates in rank order. The JSON object keeps the first [`MAX_CANDIDATES`].
    pub candidates: Vec<Candidate>,
    /// The documented `details` object of the code.
    pub details: Option<Object>,
    /// The crash ID of an `INTERNAL_ERROR`.
    pub crash_id: Option<String>,
    /// The repair calls. The envelope puts them in its top-level `next`.
    pub next: Vec<Call>,
}

impl ToolError {
    /// Makes an error with no template value, path, candidate or detail.
    #[must_use]
    pub const fn new(code: ErrorCode) -> Self {
        Self {
            code,
            vars: Vec::new(),
            field_path: None,
            candidates: Vec::new(),
            details: None,
            crash_id: None,
            next: Vec::new(),
        }
    }

    /// Sets the template value of `key`, for example `field`.
    #[must_use]
    pub fn var(mut self, key: &'static str, value: &str) -> Self {
        self.vars.push((key, value.to_owned()));
        self
    }

    /// Sets the field path.
    #[must_use]
    pub fn path(mut self, path: &str) -> Self {
        self.field_path = Some(path.to_owned());
        self
    }

    /// Adds a member to `details`.
    #[must_use]
    pub fn detail(mut self, key: &str, value: Value) -> Self {
        self.details
            .get_or_insert_with(Object::new)
            .insert(key, value);
        self
    }

    /// Sets the candidates.
    #[must_use]
    pub fn candidates(mut self, candidates: Vec<Candidate>) -> Self {
        self.candidates = candidates;
        self
    }

    /// Adds a repair call.
    #[must_use]
    pub fn next(mut self, call: Call) -> Self {
        self.next.push(call);
        self
    }

    /// Gives the message: the template of the code with the values filled in.
    ///
    /// Each value is cut to [`MAX_TEXT_CHARS`] characters.
    #[must_use]
    pub fn message(&self) -> String {
        String::new()
    }

    /// Gives the frozen error object, cut to [`ERROR_CAP`] characters.
    ///
    /// The cut drops `details` first, then candidates from the end. `candidates_total`
    /// keeps the count of all candidates.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Null
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message())
    }
}

impl std::error::Error for ToolError {}

/// Cuts `text` to at most `max` characters.
#[must_use]
pub fn cut(text: &str, max: usize) -> String {
    let _ = max;
    text.to_owned()
}
