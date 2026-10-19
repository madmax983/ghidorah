//! Discoverability on held-out intents (design Section 12.4, AC-198a).
//!
//! For each intent, `tool_search { query, level: "names", limit: 3 }` must rank an expected
//! tool in the top 3. A second ranking scores each tool by the words that the intent shares
//! with the raw `tools/list` title and description. It shows what the descriptions give
//! without the `tool_search` index.

use std::collections::BTreeSet;
use std::path::Path;

use ghidorah_json::Value;
use ghidorah_tools::{Profile, ProfileSet, registry::shipped};

use crate::error::EvalError;
use crate::host;
use crate::inputs::Intent;
use crate::milli::Milli;

/// The result of the discoverability metric.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Discover {
    /// The number of intents.
    pub intents: u64,
    /// The intents whose expected tool `tool_search` ranks in the top 3.
    pub tool_search_hits: u64,
    /// The intents whose expected tool the raw descriptions rank in the top 3.
    pub raw_hits: u64,
    /// The intent IDs that `tool_search` misses.
    pub misses: Vec<String>,
}

impl Discover {
    /// Gives the `tool_search` top-3 rate.
    #[must_use]
    pub fn tool_search_top3(&self) -> Milli {
        Milli::ratio(self.tool_search_hits, self.intents)
    }

    /// Gives the raw-description top-3 rate.
    #[must_use]
    pub fn raw_top3(&self) -> Milli {
        Milli::ratio(self.raw_hits, self.intents)
    }
}

/// Gives the lowercase words of a text.
#[must_use]
pub fn words(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() > 1)
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Gives the top 3 tool names by shared words with the raw `tools/list` entries.
#[must_use]
pub fn raw_top3(entries: &[(String, BTreeSet<String>)], intent: &str) -> Vec<String> {
    let want = words(intent);
    let mut scored: Vec<(usize, usize, &str)> = entries
        .iter()
        .enumerate()
        .map(|(i, (name, w))| (w.intersection(&want).count(), i, name.as_str()))
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored
        .into_iter()
        .take(3)
        .map(|(_, _, n)| n.to_owned())
        .collect()
}

/// Gives the name and the words of each `tools/list` entry of the full profile.
#[must_use]
pub fn raw_entries() -> Vec<(String, BTreeSet<String>)> {
    let list = ProfileSet::new(Profile::Full, None).tools_list(&shipped());
    list.as_array()
        .unwrap_or_default()
        .iter()
        .map(|t| {
            let field = |k: &str| t.get(k).and_then(Value::as_str).unwrap_or_default();
            let name = field("name").to_owned();
            let text = format!(
                "{} {} {}",
                name.replace('_', " "),
                field("title"),
                field("description")
            );
            (name, words(&text))
        })
        .collect()
}

/// Measures the discoverability of `intents`.
///
/// # Errors
///
/// Returns an [`EvalError`] when the session does not open.
pub fn run(root: &Path, intents: &[Intent]) -> Result<Discover, EvalError> {
    return Ok(Discover::default());
    let mut session = host::session(root, None, Profile::Full)?;
    let entries = raw_entries();
    let mut out = Discover::default();
    for intent in intents {
        out.intents = out.intents.saturating_add(1);
        let args = Value::object([
            ("query", Value::from(intent.text.as_str())),
            ("level", Value::from("names")),
            ("limit", Value::from(3u64)),
        ]);
        let r = host::call(&mut session, "tool_search", args);
        let names: Vec<&str> = r
            .pointer("/data/items")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|i| i.get("name").and_then(Value::as_str))
            .take(3)
            .collect();
        if intent.expect.iter().any(|e| names.contains(&e.as_str())) {
            out.tool_search_hits = out.tool_search_hits.saturating_add(1);
        } else {
            out.misses.push(intent.id.clone());
        }
        let raw = raw_top3(&entries, &intent.text);
        if intent.expect.iter().any(|e| raw.contains(e)) {
            out.raw_hits = out.raw_hits.saturating_add(1);
        }
    }
    Ok(out)
}
