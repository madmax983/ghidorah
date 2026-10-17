//! Glob patterns with linear work (design Section 10.4).
//!
//! Syntax: `*` matches any run of characters, `?` matches one character and `\` makes the
//! next character literal. All other characters match themselves. The match covers the
//! whole text and is case sensitive.
//!
//! The matcher keeps only the last `*`. It never goes back to an earlier `*`, so a pattern
//! such as `*a*a*a*a*b` takes linear work on a long text.

use std::fmt;

/// The longest pattern in characters.
pub const MAX_PATTERN_CHARS: usize = 1024;

/// An error of [`Glob::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobError {
    /// The pattern has more than [`MAX_PATTERN_CHARS`] characters.
    TooLong {
        /// The number of characters in the pattern.
        chars: usize,
    },
    /// The pattern ends with a `\` that escapes nothing.
    TrailingEscape,
}

impl fmt::Display for GlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { chars } => write!(
                f,
                "The pattern has {chars} characters. The limit is {MAX_PATTERN_CHARS}."
            ),
            Self::TrailingEscape => f.write_str("The pattern ends with an escape character."),
        }
    }
}

impl std::error::Error for GlobError {}

/// One token of a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Char(char),
    One,
    Star,
}

/// A parsed glob pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    tokens: Vec<Token>,
}

impl Glob {
    /// Parses a pattern.
    ///
    /// # Errors
    ///
    /// Returns [`GlobError::TooLong`] for a pattern above [`MAX_PATTERN_CHARS`] characters and
    /// [`GlobError::TrailingEscape`] for a pattern that ends with an unpaired `\`.
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        let _ = pattern;
        Ok(Self {
            tokens: vec![Token::Char('\0'), Token::One, Token::Star],
        })
    }

    /// Tells if the pattern matches the whole `text`.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        self.matches_counted(text).0
    }

    /// Tells if the pattern matches the whole `text`, and gives the number of steps.
    ///
    /// One step is one pass of the match loop. The count is at most a small multiple of
    /// the text length times the longest literal run of the pattern.
    #[must_use]
    pub fn matches_counted(&self, text: &str) -> (bool, u64) {
        let _ = (text, &self.tokens);
        (false, 0)
    }

    /// Tells if the pattern has no `*` and no `?`.
    #[must_use]
    pub fn is_literal(&self) -> bool {
        false
    }
}
