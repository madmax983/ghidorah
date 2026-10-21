//! The `tool_search` index, the synonyms and the topics (design Section 10.4, ADR-0005).
//!
//! Ranking is deterministic. Each query token adds the weight of the best field that holds it:
//!
//! | Field | Weight |
//! |---|---|
//! | The whole tool name, after the synonyms | 40 |
//! | A part of the tool name (split at `_`) | 10 |
//! | A keyword of [`KEYWORDS`] | 6 |
//! | A word of the summary (the first sentence) | 4 |
//! | A word of an action line or an argument name | 2 |
//! | A word of the description or of the example arguments | 1 |
//!
//! Query tokens are lower case runs of letters and digits. [`STOP_WORDS`] do not count.
//! [`SYNONYMS`] map a token to another token or to a tool name. Ties sort by registry order.
//! A query with no token lists every active tool.

mod topics;
mod words;

use std::collections::BTreeSet;

use ghidorah_json::{Limits, Object, Value};

pub use topics::TOPICS;
pub use words::{KEYWORDS, STOP_WORDS, SYNONYMS};

use crate::profiles::ProfileSet;
use crate::schema::input_schema;
use crate::spec::ToolSpec;

/// The detail level of a result item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// The name and the annotations.
    Names,
    /// The name, the summary and the annotations.
    Summaries,
    /// The name, the summary, the input schema, one example per action and the annotations.
    Full,
}

impl Level {
    /// All levels.
    pub const ALL: [Self; 3] = [Self::Names, Self::Summaries, Self::Full];

    /// Gives the level name: `names`, `summaries` or `full`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Names => "names",
            Self::Summaries => "summaries",
            Self::Full => "full",
        }
    }

    /// Parses a level name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.name() == text)
    }
}

/// One topic: a concept text for agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topic {
    /// The topic name.
    pub name: &'static str,
    /// The text: at most [`MAX_TOPIC_CHARS`] characters of STE.
    pub text: &'static str,
}

/// The largest topic text in characters (AC-152b).
pub const MAX_TOPIC_CHARS: usize = 2_000;

/// The topic names in schema order.
pub const TOPIC_NAMES: [&str; 9] = [
    "addresses",
    "ids",
    "budgets",
    "batch",
    "errors",
    "rules",
    "relations",
    "profiles",
    "resume",
];

/// The weight of a match of the whole tool name.
pub const WEIGHT_NAME: u64 = 40;

/// The weight of a match of a part of the tool name.
pub const WEIGHT_NAME_PART: u64 = 10;

/// The weight of a match of a keyword.
pub const WEIGHT_KEYWORD: u64 = 6;

/// The weight of a match of a summary word.
pub const WEIGHT_SUMMARY: u64 = 4;

/// The weight of a match of an action line word or an argument name.
pub const WEIGHT_ACTION: u64 = 2;

/// The weight of a match of a description word or an example word.
pub const WEIGHT_TEXT: u64 = 1;

/// Gives the topic `name`, or `None`.
#[must_use]
pub fn topic(name: &str) -> Option<&'static Topic> {
    TOPICS.iter().find(|t| t.name == name)
}

/// Gives the lower case tokens of `text`: runs of ASCII letters and digits.
#[must_use]
pub fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Gives the query tokens of `text`: [`tokens`] without [`STOP_WORDS`], with [`SYNONYMS`],
/// in first-seen order and without duplicates.
#[must_use]
pub fn query_tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in tokens(text) {
        if STOP_WORDS.contains(&token.as_str()) {
            continue;
        }
        let token = SYNONYMS
            .iter()
            .find(|(word, _)| *word == token)
            .map_or(token, |(_, target)| (*target).to_owned());
        if !out.contains(&token) {
            out.push(token);
        }
    }
    out
}

/// The token fields of one tool, one set per weight.
struct Fields {
    name_parts: BTreeSet<String>,
    keywords: BTreeSet<String>,
    summary: BTreeSet<String>,
    actions: BTreeSet<String>,
    text: BTreeSet<String>,
}

impl Fields {
    fn of<S: 'static>(tool: &ToolSpec<S>) -> Self {
        let set = |text: &str| tokens(text).into_iter().collect::<BTreeSet<String>>();
        let keywords = KEYWORDS
            .iter()
            .filter(|(name, _)| *name == tool.name)
            .flat_map(|(_, words)| words.iter().map(|w| (*w).to_owned()))
            .collect();
        let mut actions = BTreeSet::new();
        for action in tool.actions {
            actions.extend(set(action.value));
            actions.extend(set(action.line));
        }
        for spec in tool.args {
            actions.extend(set(spec.name));
        }
        let mut text = set(tool.description);
        for example in tool.examples {
            text.extend(set(example.args));
        }
        Self {
            name_parts: set(tool.name),
            keywords,
            summary: set(tool.summary),
            actions,
            text,
        }
    }

    /// Gives the weight of the best field that holds `token`, or 0.
    fn weight(&self, tool: &str, token: &str) -> u64 {
        let fields = [
            (WEIGHT_NAME_PART, &self.name_parts),
            (WEIGHT_KEYWORD, &self.keywords),
            (WEIGHT_SUMMARY, &self.summary),
            (WEIGHT_ACTION, &self.actions),
            (WEIGHT_TEXT, &self.text),
        ];
        if token == tool {
            return WEIGHT_NAME;
        }
        fields
            .iter()
            .find(|(_, set)| set.contains(token))
            .map_or(0, |(w, _)| *w)
    }
}

/// Gives the score of `tool` for the query tokens `query`.
#[must_use]
pub fn score<S: 'static>(tool: &ToolSpec<S>, query: &[String]) -> u64 {
    let fields = Fields::of(tool);
    query
        .iter()
        .map(|token| fields.weight(tool.name, token))
        .sum()
}

/// Ranks `tools` for `query`: `(position in tools, score)` by score from high to low, then by
/// position. A query with tokens keeps only the tools with a score above 0.
#[must_use]
pub fn rank<S: 'static>(tools: &[&'static ToolSpec<S>], query: &str) -> Vec<(usize, u64)> {
    let query = query_tokens(query);
    let mut out: Vec<(usize, u64)> = tools
        .iter()
        .enumerate()
        .map(|(i, tool)| (i, score(tool, &query)))
        .filter(|(_, s)| query.is_empty() || *s > 0)
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

/// Gives the examples of the full level: one example per action, or the first example of a
/// tool with no action.
fn examples<S: 'static>(tool: &ToolSpec<S>) -> Value {
    let parse = |text: &str| ghidorah_json::parse(text, &Limits::DEFAULT).unwrap_or_default();
    let list: Vec<Value> = if tool.actions.is_empty() {
        tool.examples
            .first()
            .map(|e| Value::object([("args", parse(e.args))]))
            .into_iter()
            .collect()
    } else {
        tool.actions
            .iter()
            .map(|a| Value::object([("action", Value::from(a.value)), ("args", parse(a.example))]))
            .collect()
    };
    Value::Array(list)
}

/// Gives the result item of `tool` at `level` in `profile`.
#[must_use]
pub fn item<S: 'static>(tool: &ToolSpec<S>, level: Level, profile: &ProfileSet) -> Value {
    let mut out = Object::new();
    out.push("name", Value::from(tool.name));
    if level != Level::Names {
        out.push("summary", Value::from(tool.summary));
    }
    if level == Level::Full {
        out.push("schema", input_schema(tool));
        out.push("examples", examples(tool));
    }
    let mut hints = profile.annotations(tool);
    if let Some(object) = hints.as_object_mut() {
        let _ = object.remove("title");
    }
    out.push("annotations", hints);
    Value::Object(out)
}
