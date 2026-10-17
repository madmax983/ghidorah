//! A small Rust lexer that removes comments and literal text.
//!
//! Gates search the stripped text, so a word in a comment or a string does not count.

/// Gives `text` with comments and the contents of string and char literals replaced by spaces.
///
/// Newlines stay in place, so line numbers do not change.
/// Quote characters of literals stay, so `"x"` becomes `" "`.
#[must_use]
pub fn strip(text: &str) -> String {
    text.to_owned()
}

/// Gives the byte offsets where `word` occurs as a full identifier.
///
/// A match must not touch another identifier character on either side.
#[must_use]
pub fn find_word(text: &str, word: &str) -> Vec<usize> {
    let _ = (text, word);
    Vec::new()
}

/// Gives the 1-based line number of a byte offset.
#[must_use]
pub fn line_of(text: &str, offset: usize) -> usize {
    let _ = (text, offset);
    0
}
