//! The word lists of the checker: imperative verbs and banned words.

use std::collections::BTreeSet;

use super::lex::norm;
use super::words::{BANNED, IMPERATIVES};

/// The word lists of the checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lexicon {
    imperatives: BTreeSet<String>,
    banned: BTreeSet<String>,
}

impl Lexicon {
    /// Returns the built-in lexicon: the imperative verbs and the ban list of ADR-0019.
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            imperatives: IMPERATIVES.iter().map(ToString::to_string).collect(),
            banned: BANNED.iter().map(ToString::to_string).collect(),
        }
    }

    /// Adds the words of a ban list file.
    pub fn add_banlist(&mut self, text: &str) {
        for line in text.lines() {
            let word = norm(line);
            if !line.trim_start().starts_with('#') && !word.is_empty() {
                self.banned.insert(word);
            }
        }
    }

    /// Adds the verbs of a glossary file.
    ///
    /// The file can mark a verb in three forms:
    ///
    /// - a table row whose second cell is `verb`;
    /// - a list item `- word (verb)`;
    /// - a table row under a heading `Technical verbs`.
    ///
    /// The first cell or the item word is the verb. The header row of a table
    /// and a cell with more than one word give no verb.
    pub fn add_glossary(&mut self, text: &str) {
        let mut in_verbs = false;
        let mut lines = text.lines().map(str::trim).peekable();
        while let Some(line) = lines.next() {
            if line.starts_with('#') {
                in_verbs = line
                    .trim_start_matches('#')
                    .trim()
                    .eq_ignore_ascii_case(VERB_HEADING);
                continue;
            }
            let header = lines.peek().is_some_and(|next| is_separator_row(next));
            let word = if in_verbs && !header {
                first_cell(line).or_else(|| glossary_verb(line))
            } else {
                glossary_verb(line)
            };
            if let Some(word) = word {
                self.imperatives.insert(word);
            }
        }
    }

    /// Returns `true` when `word` is an imperative verb, in any letter case.
    #[must_use]
    pub fn is_imperative(&self, word: &str) -> bool {
        self.imperatives.contains(&norm(word))
    }

    /// Returns `true` when `word` or its base form is on the ban list, in any letter case.
    #[must_use]
    pub fn is_banned(&self, word: &str) -> bool {
        let word = norm(word);
        if self.banned.contains(&word) {
            return true;
        }
        let stems = [
            word.strip_suffix("es"),
            word.strip_suffix('s'),
            word.strip_suffix("ed"),
            word.strip_suffix('d'),
            word.strip_suffix("ing"),
        ];
        let with_e = word.strip_suffix("ing").map(|stem| format!("{stem}e"));
        stems.into_iter().flatten().any(|s| self.banned.contains(s))
            || with_e.is_some_and(|s| self.banned.contains(&s))
    }
}

/// The glossary heading whose table rows are verbs.
const VERB_HEADING: &str = "Technical verbs";

/// Returns `true` for the separator row of a Markdown table, for example `|---|---|`.
fn is_separator_row(line: &str) -> bool {
    line.starts_with('|')
        && line.contains('-')
        && line.chars().all(|c| matches!(c, '|' | '-' | ':' | ' '))
}

/// Returns the word of the first cell of a table row.
///
/// A separator row and a cell with more than one word give no word.
fn first_cell(line: &str) -> Option<String> {
    let row = line.strip_prefix('|')?;
    if is_separator_row(line) {
        return None;
    }
    let word = row.split('|').next()?.trim().trim_matches(['`', '*']);
    (!word.is_empty() && !word.contains(' ')).then(|| norm(word))
}

/// Returns the verb that a glossary line defines.
fn glossary_verb(line: &str) -> Option<String> {
    if let Some(row) = line.strip_prefix('|') {
        let mut cells = row.split('|').map(|c| c.trim().trim_matches(['`', '*']));
        let word = cells.next()?;
        let kind = cells.next()?;
        return (kind.eq_ignore_ascii_case("verb") && !word.contains(' ') && !word.is_empty())
            .then(|| norm(word));
    }
    let item = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))?
        .trim_start();
    let (word, rest) = item.split_once(char::is_whitespace)?;
    rest.trim_start()
        .starts_with("(verb")
        .then(|| norm(word.trim_matches(['`', '*'])))
        .filter(|w| !w.is_empty())
}
