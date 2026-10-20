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
use std::ops::{Deref, DerefMut};

use ghidorah_base::ErrorCode;
use ghidorah_base::catalog::render;
use ghidorah_json::{Number, Object, Value};

use crate::content::chars;
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

    /// Gives the JSON form of the candidate. Each text is cut to [`MAX_TEXT_CHARS`].
    #[must_use]
    pub fn to_json(&self) -> Value {
        let value = match &self.value {
            Value::String(text) => Value::from(cut(text, MAX_TEXT_CHARS)),
            Value::Null | Value::Bool(_) | Value::Number(_) => self.value.clone(),
            Value::Array(_) | Value::Object(_) => {
                let text = ghidorah_json::write(&self.value);
                if text.chars().count() <= MAX_TEXT_CHARS {
                    self.value.clone()
                } else {
                    Value::Null
                }
            }
        };
        let mut out = Object::new();
        out.push("value", value);
        out.push("label", Value::from(cut(&self.label, MAX_TEXT_CHARS)));
        let optional = [("id", &self.id), ("addr", &self.addr), ("kind", &self.kind)];
        for (key, text) in optional {
            if let Some(text) = text {
                out.push(key, Value::from(cut(text, MAX_TEXT_CHARS)));
            }
        }
        Value::Object(out)
    }
}

/// One tool error.
///
/// The error keeps its parts in a box, so a `Result` with it stays small.
/// Field access goes through `Deref` to [`ErrorParts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError(Box<ErrorParts>);

/// The parts of one tool error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorParts {
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
    /// `true` makes the error object take the plain hint of the code.
    pub plain: bool,
}

impl Deref for ToolError {
    type Target = ErrorParts;

    fn deref(&self) -> &ErrorParts {
        &self.0
    }
}

impl DerefMut for ToolError {
    fn deref_mut(&mut self) -> &mut ErrorParts {
        &mut self.0
    }
}

impl ToolError {
    /// Makes an error with no template value, path, candidate or detail.
    #[must_use]
    pub fn new(code: ErrorCode) -> Self {
        Self(Box::new(ErrorParts {
            code,
            vars: Vec::new(),
            field_path: None,
            candidates: Vec::new(),
            details: None,
            crash_id: None,
            next: Vec::new(),
            plain: false,
        }))
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
        let _ = self
            .details
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

    /// Makes the error object take the plain hint of the code. A handler calls it when the
    /// hint does not apply, for example when the scope is already wide.
    #[must_use]
    pub fn plain_hint(mut self) -> Self {
        self.plain = true;
        self
    }

    /// Gives the template values, each cut to [`MAX_TEXT_CHARS`] characters.
    fn values(&self) -> Vec<(&'static str, String)> {
        self.vars
            .iter()
            .map(|(key, value)| (*key, cut(value, MAX_TEXT_CHARS)))
            .collect()
    }

    /// Gives the hint of the error object.
    ///
    /// The plain hint of the code replaces the hint in three cases:
    ///
    /// - The error asks for it with [`ToolError::plain_hint`].
    /// - The hint names `next[0]`, and `has_next` is `false`.
    /// - The hint names the candidates, and the error has none.
    ///
    /// The template values fill the placeholders.
    #[must_use]
    pub fn hint(&self, has_next: bool) -> String {
        let info = self.code.info();
        let plain = self.plain
            || (info.hint_names_next() && !has_next)
            || (info.hint_names_candidates() && self.candidates.is_empty());
        let text = if plain { info.plain } else { info.hint };
        let values = self.values();
        let pairs: Vec<(&str, &str)> = values.iter().map(|(k, v)| (*k, v.as_str())).collect();
        render(text, &pairs)
    }

    /// Gives the message: the template of the code with the values filled in.
    ///
    /// Each value is cut to [`MAX_TEXT_CHARS`] characters.
    #[must_use]
    pub fn message(&self) -> String {
        let values = self.values();
        let pairs: Vec<(&str, &str)> = values.iter().map(|(k, v)| (*k, v.as_str())).collect();
        render(self.code.info().message, &pairs)
    }

    /// Gives the frozen error object, cut to [`ERROR_CAP`] characters.
    ///
    /// The hint counts the repair calls of the error as `next`. The cut drops `details`
    /// first, then candidates from the end. `candidates_total` keeps the count of all
    /// candidates.
    #[must_use]
    pub fn to_json(&self) -> Value {
        self.to_json_with(!self.next.is_empty())
    }

    /// Gives the frozen error object of an envelope. `has_next` tells if the envelope has
    /// valid `next` calls.
    #[must_use]
    pub fn to_json_with(&self, has_next: bool) -> Value {
        let hint = self.hint(has_next);
        let mut shown = self.candidates.len().min(MAX_CANDIDATES);
        let mut details = self.details.is_some();
        loop {
            let object = self.object(&hint, shown, details);
            let fits = chars(&ghidorah_json::write(&object)) <= ERROR_CAP;
            if fits || (!details && shown == 0) {
                return object;
            }
            if details {
                details = false;
            } else {
                shown -= 1;
            }
        }
    }

    /// Builds the object with `hint`, the first `shown` candidates, and with or without
    /// `details`.
    fn object(&self, hint: &str, shown: usize, details: bool) -> Value {
        let info = self.code.info();
        let mut out = Object::new();
        out.push("code", Value::from(info.name));
        out.push("num", int(u64::from(info.num)));
        out.push("message", Value::from(self.message()));
        out.push("hint", Value::from(hint));
        out.push("retryable", Value::Bool(info.retry));
        if let Some(path) = &self.field_path {
            out.push("field_path", Value::from(cut(path, MAX_PATH_CHARS)));
        }
        if !self.candidates.is_empty() {
            let list = self.candidates.iter().take(shown).map(Candidate::to_json);
            out.push("candidates", Value::Array(list.collect()));
            out.push("candidates_total", count(self.candidates.len()));
        }
        match (&self.details, details) {
            (Some(object), true) => out.push("details", Value::Object(object.clone())),
            (Some(_), false) => {
                out.push("details", Value::object([("truncated", Value::Bool(true))]));
            }
            (None, _) => {}
        }
        if let Some(id) = &self.crash_id {
            out.push("crash_id", Value::from(id.as_str()));
        }
        Value::Object(out)
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message())
    }
}

impl std::error::Error for ToolError {}

/// Gives a JSON integer.
pub(crate) fn int(value: u64) -> Value {
    Number::parse(&value.to_string()).map_or(Value::Null, Value::Number)
}

/// Gives a JSON integer of a count.
pub(crate) fn count(value: usize) -> Value {
    int(u64::try_from(value).unwrap_or(u64::MAX))
}

/// Cuts `text` to at most `max` characters.
#[must_use]
pub fn cut(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}
