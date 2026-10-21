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
//!
//! The error object of a call drops each hint sentence that names a tool of the [`Inactive`]
//! set of the call ([`ToolError::to_json_in`]). The error of an item of a list input takes
//! the same set ([`ToolError::item_json`]).

use std::collections::BTreeSet;
use std::fmt;
use std::ops::{Deref, DerefMut};

use ghidorah_base::catalog::render;
use ghidorah_base::{ErrorCode, Fuel, did_you_mean, word_matches};
use ghidorah_json::{Number, Object, Value};

use crate::content::chars;
use crate::hints::{Call, WHY_ALTERNATIVE};
use crate::registry::Registry;
use crate::spec::Profile;

/// The largest error object in characters.
pub const ERROR_CAP: u64 = 10_000;

/// The largest number of candidates in an error object.
pub const MAX_CANDIDATES: usize = 5;

/// The largest template value, label or candidate value in characters.
pub const MAX_TEXT_CHARS: usize = 256;

/// The largest `field_path` in characters.
pub const MAX_PATH_CHARS: usize = 512;

/// The registered tools outside the active profile of one call (design Section 10.8).
///
/// An error object drops each hint sentence that names a tool of this set. The empty set
/// keeps every sentence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inactive(BTreeSet<&'static str>);

impl Inactive {
    /// Gives the tools of `registry` that `in_profile` does not hold.
    #[must_use]
    pub fn of<S: 'static>(registry: &Registry<S>, in_profile: &dyn Fn(&str) -> bool) -> Self {
        Self(
            registry
                .names()
                .into_iter()
                .filter(|name| !in_profile(name))
                .collect(),
        )
    }

    /// Gives the shipped tools that a shipped profile leaves out. An error object outside a
    /// call takes this set, so its hint names only tools of every profile.
    #[must_use]
    pub fn any_profile() -> Self {
        let tools = crate::registry::shipped().tools();
        let partial = tools
            .iter()
            .filter(|t| !Profile::ALL.iter().all(|p| t.profiles.contains(p)));
        Self(partial.map(|t| t.name).collect())
    }

    /// Tells if `word` is the name of a tool of the set.
    #[must_use]
    pub fn names(&self, word: &str) -> bool {
        self.0.contains(word)
    }
}

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

    /// Gives the hint of the error object outside a call: each sentence that names a tool
    /// outside a shipped profile drops out ([`Inactive::any_profile`]).
    #[must_use]
    pub fn hint(&self, has_next: bool) -> String {
        self.hint_in(has_next, &Inactive::any_profile())
    }

    /// Gives the hint of the error object for the active tools.
    ///
    /// The plain hint of the code replaces the hint in three cases:
    ///
    /// - The error asks for it with [`ToolError::plain_hint`].
    /// - The hint names `next[0]`, and `has_next` is `false`.
    /// - The hint names the candidates, and the error has none.
    ///
    /// A sentence that names a tool of `inactive` drops out. So the hint sends the agent to
    /// no tool outside the profile. A catalog text that names a tool also has a sentence that
    /// names no tool. The template values fill the placeholders.
    #[must_use]
    pub fn hint_in(&self, has_next: bool, inactive: &Inactive) -> String {
        let info = self.code.info();
        let plain = self.plain
            || (info.hint_names_next() && !has_next)
            || (info.hint_names_candidates() && self.candidates.is_empty());
        let text = if plain { info.plain } else { info.hint };
        let values = self.values();
        let pairs: Vec<(&str, &str)> = values.iter().map(|(k, v)| (*k, v.as_str())).collect();
        render(&active_sentences(text, inactive), &pairs)
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

    /// Gives the frozen error object outside a call, for example the error of a request line
    /// that names no tool. Each hint sentence that names a tool outside a shipped profile
    /// drops out ([`Inactive::any_profile`]).
    ///
    /// The error object of a call uses the [`Inactive`] set of the call instead
    /// ([`ToolError::to_json_in`] and [`ToolError::item_json`]). So an error object that
    /// skips the set of its call still names no tool outside a profile.
    #[must_use]
    pub fn to_json(&self) -> Value {
        self.to_json_in(!self.next.is_empty(), &Inactive::any_profile())
    }

    /// Gives the error object of one item of a list input with the hint for the active tools
    /// (AC-144). The hint counts the repair calls of the error as `next`.
    #[must_use]
    pub fn item_json(&self, inactive: &Inactive) -> Value {
        self.to_json_in(!self.next.is_empty(), inactive)
    }

    /// Gives the frozen error object of an envelope with the hint for the active tools (see
    /// [`ToolError::hint_in`]), cut to [`ERROR_CAP`] characters. `has_next` tells if the
    /// envelope has valid `next` calls.
    ///
    /// The cut drops `details` first, then candidates from the end. `candidates_total` keeps
    /// the count of all candidates.
    #[must_use]
    pub fn to_json_in(&self, has_next: bool, inactive: &Inactive) -> Value {
        let hint = self.hint_in(has_next, inactive);
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

/// Gives the sentences of the catalog text `text` that name no inactive tool. A word is a run
/// of ASCII letters, digits and `_`. When each sentence names an inactive tool, the text is
/// empty.
fn active_sentences(text: &str, inactive: &Inactive) -> String {
    let kept: String = text
        .split_inclusive(". ")
        .filter(|sentence| {
            !sentence
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|word| inactive.names(word))
        })
        .collect();
    kept.trim_end().to_owned()
}

/// Cuts `text` to at most `max` characters.
#[must_use]
pub fn cut(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// The fuel of the did-you-mean scan of a tool name.
const DYM_FUEL: u64 = 100_000;

/// Gives the candidates of the tool name `tool` from `names`.
///
/// The candidates are the names near `tool` ([`did_you_mean`]). With no near name, they are
/// the names that share a full word with `tool` ([`word_matches`]), for example
/// `history_undo` for `undo`.
pub(crate) fn tool_candidates(tool: &str, names: &[&str]) -> Vec<Candidate> {
    let mut fuel = Fuel::new(DYM_FUEL);
    let near: Vec<String> = did_you_mean(tool, names.iter().copied(), &mut fuel)
        .into_iter()
        .map(|s| s.name)
        .collect();
    let found = if near.is_empty() {
        let mut fuel = Fuel::new(DYM_FUEL);
        word_matches(tool, names.iter().copied(), &mut fuel)
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        near
    };
    found
        .iter()
        .map(|name| Candidate::text(name, "tool"))
        .collect()
}

/// Gives the name of the active tool set for a hint, for example `the mini profile`.
///
/// `in_profile` tells if the active set holds a tool. A set that matches no profile of the
/// registry, for example a `--tools` list, gives `a --tools list`.
pub(crate) fn profile_label<S: 'static>(
    registry: &Registry<S>,
    in_profile: &dyn Fn(&str) -> bool,
) -> String {
    Profile::ALL
        .into_iter()
        .find(|p| {
            registry
                .tools()
                .iter()
                .all(|t| in_profile(t.name) == t.profiles.contains(p))
        })
        .map_or_else(
            || "a --tools list".to_owned(),
            |p| format!("the {} profile", p.as_str()),
        )
}

/// Gives the `TOOL_NOT_IN_PROFILE` error of `tool` with the reason `not_in_profile`.
///
/// The hint names the active tool set. The candidates are the active tools with close names
/// or a shared name word ([`tool_candidates`]).
/// The repair call searches the active tools for the name. The pipeline drops it when the
/// profile has no `tool_search`.
pub(crate) fn not_in_profile<S: 'static>(
    registry: &Registry<S>,
    in_profile: &dyn Fn(&str) -> bool,
    tool: &str,
) -> ToolError {
    let names: Vec<&str> = registry
        .names()
        .into_iter()
        .filter(|name| in_profile(name))
        .collect();
    let candidates = tool_candidates(tool, &names);
    let query = Value::object([("query", Value::from(tool))]);
    ToolError::new(ErrorCode::ToolNotInProfile)
        .var("tool", tool)
        .var("profile", &profile_label(registry, in_profile))
        .detail("reason", Value::from("not_in_profile"))
        .candidates(candidates)
        .next(Call::new("tool_search", query, WHY_ALTERNATIVE))
}
