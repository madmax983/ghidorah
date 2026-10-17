//! The parse error type and its stable codes.

use std::fmt;

/// The stable code of a parse error.
///
/// Each code has an `UPPER_SNAKE` text form that never changes, for example `E_DEPTH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Code {
    /// The text ends before the value is complete.
    Eof,
    /// A byte is not valid at its position.
    Syntax,
    /// The nesting depth of arrays and objects is more than the limit.
    Depth,
    /// The text is longer than the byte limit.
    Size,
    /// A number does not match the JSON number grammar.
    Number,
    /// A string holds a control character (U+0000 to U+001F) without an escape.
    Control,
    /// An escape sequence in a string is not valid.
    Escape,
    /// A `\u` escape gives a surrogate that has no pair.
    Surrogate,
    /// The bytes are not valid UTF-8.
    Utf8,
    /// Data follows the end of the top value.
    Trailing,
}

impl Code {
    /// All codes, in declaration order.
    pub const ALL: [Self; 10] = [
        Self::Eof,
        Self::Syntax,
        Self::Depth,
        Self::Size,
        Self::Number,
        Self::Control,
        Self::Escape,
        Self::Surrogate,
        Self::Utf8,
        Self::Trailing,
    ];

    /// Gives the stable text form, for example `E_DEPTH`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eof => "E_EOF",
            Self::Syntax => "E_SYNTAX",
            Self::Depth => "E_DEPTH",
            Self::Size => "E_SIZE",
            Self::Number => "E_NUMBER",
            Self::Control => "E_CONTROL",
            Self::Escape => "E_ESCAPE",
            Self::Surrogate => "E_SURROGATE",
            Self::Utf8 => "E_UTF8",
            Self::Trailing => "E_TRAILING",
        }
    }

    /// Gives the message of the code in one sentence.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Eof => "The text ends before the value is complete.",
            Self::Syntax => "The byte is not valid at this position.",
            Self::Depth => "The nesting depth is more than the limit.",
            Self::Size => "The text is longer than the byte limit.",
            Self::Number => "The number does not match the JSON grammar.",
            Self::Control => "The string holds a control character without an escape.",
            Self::Escape => "The escape sequence is not valid.",
            Self::Surrogate => "The string holds a surrogate that has no pair.",
            Self::Utf8 => "The bytes are not valid UTF-8.",
            Self::Trailing => "Data follows the end of the value.",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parse error: a stable code and the byte offset where the parser found the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonError {
    /// The stable code.
    pub code: Code,
    /// The byte offset in the input text.
    pub offset: usize,
}

impl JsonError {
    /// Makes an error with `code` at `offset`.
    #[must_use]
    pub const fn new(code: Code, offset: usize) -> Self {
        Self { code, offset }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at byte {}: {}",
            self.code.as_str(),
            self.offset,
            self.code.message()
        )
    }
}

impl std::error::Error for JsonError {}
