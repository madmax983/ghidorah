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

use ghidorah_json::Value;

use crate::profiles::ProfileSet;
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

/// The topics in the order of [`TOPIC_NAMES`].
pub const TOPICS: &[Topic] = &[];

/// Words that do not count in a query.
pub const STOP_WORDS: &[&str] = &[];

/// Query synonyms: a token and the token or tool name that it stands for.
pub const SYNONYMS: &[(&str, &str)] = &[];

/// Search keywords of each tool of the catalog.
pub const KEYWORDS: &[(&str, &[&str])] = &[];

/// Gives the topic `name`, or `None`.
#[must_use]
pub fn topic(name: &str) -> Option<&'static Topic> {
    TOPICS.iter().find(|t| t.name == name)
}

/// Gives the lower case tokens of `text`: runs of ASCII letters and digits.
#[must_use]
pub fn tokens(text: &str) -> Vec<String> {
    let _ = text;
    Vec::new()
}

/// Gives the query tokens of `text`: [`tokens`] without [`STOP_WORDS`], with [`SYNONYMS`],
/// in first-seen order and without duplicates.
#[must_use]
pub fn query_tokens(text: &str) -> Vec<String> {
    let _ = text;
    Vec::new()
}

/// Gives the score of `tool` for the query tokens `query`.
#[must_use]
pub fn score<S: 'static>(tool: &ToolSpec<S>, query: &[String]) -> u64 {
    let _ = (tool, query);
    0
}

/// Ranks `tools` for `query`: `(position in tools, score)` by score from high to low, then by
/// position. A query with tokens keeps only the tools with a score above 0.
#[must_use]
pub fn rank<S: 'static>(tools: &[&'static ToolSpec<S>], query: &str) -> Vec<(usize, u64)> {
    let _ = (tools, query);
    Vec::new()
}

/// Gives the result item of `tool` at `level` in `profile`.
#[must_use]
pub fn item<S: 'static>(tool: &ToolSpec<S>, level: Level, profile: &ProfileSet) -> Value {
    let _ = (tool, level, profile);
    Value::Null
}
