//! The reviewed allowlist of warn mode.

use std::fmt;

use super::{Finding, Rule};

/// The number of sentence words that an entry fragment holds.
const FRAGMENT_WORDS: usize = 8;

/// One allowlist entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllowEntry {
    /// The repository path with `/` separators.
    pub path: String,
    /// The allowed rule.
    pub rule: Rule,
    /// A text that the sentence contains.
    pub fragment: String,
}

impl AllowEntry {
    /// Makes the entry that allows `finding` in `path`.
    ///
    /// The fragment is the first 8 words of the sentence.
    #[must_use]
    pub fn for_finding(path: &str, finding: &Finding) -> Self {
        let words: Vec<&str> = finding
            .sentence
            .split_whitespace()
            .take(FRAGMENT_WORDS)
            .collect();
        Self {
            path: path.to_string(),
            rule: finding.rule,
            fragment: words.join(" "),
        }
    }

    /// Returns `true` when the entry allows `finding` in `path`.
    #[must_use]
    pub fn allows(&self, path: &str, finding: &Finding) -> bool {
        self.path == path && self.rule == finding.rule && finding.sentence.contains(&self.fragment)
    }
}

impl fmt::Display for AllowEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.path, self.rule, self.fragment)
    }
}

/// An allowlist line that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistError {
    /// The 1-based line.
    pub line: usize,
    /// What is wrong with the line.
    pub message: String,
}

impl fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "allowlist line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for AllowlistError {}

/// The reviewed allowlist of warn mode.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allowlist {
    entries: Vec<AllowEntry>,
}

/// Splits `text` at the first white space and trims the rest.
fn split_word(text: &str) -> Option<(&str, &str)> {
    text.split_once(char::is_whitespace)
        .map(|(word, rest)| (word, rest.trim()))
}

impl Allowlist {
    /// Parses the allowlist format of this module.
    ///
    /// # Errors
    ///
    /// Returns [`AllowlistError`] for a line with no path, an unknown rule or no fragment.
    pub fn parse(text: &str) -> Result<Self, AllowlistError> {
        let mut entries = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fail = |message: &str| AllowlistError {
                line: i + 1,
                message: message.to_string(),
            };
            let (path, rest) = split_word(line).ok_or_else(|| fail("no rule after the path"))?;
            let (id, fragment) =
                split_word(rest).ok_or_else(|| fail("no fragment after the rule"))?;
            let rule = Rule::from_id(id).ok_or_else(|| fail(&format!("unknown rule {id}")))?;
            if fragment.is_empty() {
                return Err(fail("no fragment after the rule"));
            }
            entries.push(AllowEntry {
                path: path.to_string(),
                rule,
                fragment: fragment.to_string(),
            });
        }
        Ok(Self { entries })
    }

    /// Returns the entries in file order.
    #[must_use]
    pub fn entries(&self) -> &[AllowEntry] {
        &self.entries
    }

    /// Returns the index of the first entry that allows `finding` in `path`.
    #[must_use]
    pub fn matching(&self, path: &str, finding: &Finding) -> Option<usize> {
        self.entries.iter().position(|e| e.allows(path, finding))
    }

    /// Returns `true` when an entry allows `finding` in `path`.
    #[must_use]
    pub fn allows(&self, path: &str, finding: &Finding) -> bool {
        self.matching(path, finding).is_some()
    }
}
