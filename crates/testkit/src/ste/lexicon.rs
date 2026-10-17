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
    /// A verb is a table row whose second cell is `verb`, or a list item
    /// `- word (verb)`. The first cell or the item word is the verb.
    pub fn add_glossary(&mut self, text: &str) {
        for line in text.lines() {
            if let Some(word) = glossary_verb(line.trim()) {
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
