//! Content blocks and result sizes (design Sections 10.9 and 10.10).
//!
//! | Mode | Result | Copies |
//! |---|---|---|
//! | [`ContentMode::Plain`] | The envelope alone: CLI stdout and `jsonl` lines | 1 |
//! | [`ContentMode::Structured`] | `structuredContent` and an empty `content` list | 1 |
//! | [`ContentMode::Text`] | One text block with the compact envelope | 1 |
//! | [`ContentMode::Both`] | `structuredContent` and one text block | 2 |
//!
//! A text block holds the envelope as a JSON string. So each `"` and `\` of the envelope costs
//! one more character in that copy. [`cost`] counts every copy exactly.

use ghidorah_json::Value;

/// The content mode of one result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum ContentMode {
    /// The envelope alone (CLI and `jsonl`).
    #[default]
    Plain,
    /// MCP `structuredContent` only.
    Structured,
    /// MCP text block only.
    Text,
    /// MCP `structuredContent` and a text block.
    Both,
}

impl ContentMode {
    /// All modes.
    pub const ALL: [Self; 4] = [Self::Plain, Self::Structured, Self::Text, Self::Both];

    /// Gives the number of envelope copies in the result: 2 for [`ContentMode::Both`], else 1.
    #[must_use]
    pub const fn copies(self) -> u64 {
        match self {
            Self::Both => 2,
            Self::Plain | Self::Structured | Self::Text => 1,
        }
    }

    /// Parses the value of the server flag `--content`: `both`, `structured` or `text`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let _ = text;
        None
    }
}

/// Gives the number of characters of `text`.
#[must_use]
pub fn chars(text: &str) -> u64 {
    let _ = text;
    0
}

/// Gives the number of characters of compact JSON `json` inside a JSON string.
///
/// Each `"` and `\` gains one escape character. Compact JSON holds no raw control character.
#[must_use]
pub fn escaped_chars(json: &str) -> u64 {
    let _ = json;
    0
}

/// Gives the characters that the compact JSON fragment `json` adds to a result in `mode`.
#[must_use]
pub fn cost(json: &str, mode: ContentMode) -> u64 {
    let _ = (json, mode);
    0
}

/// Gives the result of one tool call in `mode` for the envelope `envelope`.
///
/// `is_error` sets the MCP `isError` member. [`ContentMode::Plain`] gives the envelope itself.
#[must_use]
pub fn tool_result(envelope: &Value, is_error: bool, mode: ContentMode) -> Value {
    let _ = (is_error, mode);
    envelope.clone()
}

/// Gives the exact size in characters of the serialized result of [`tool_result`].
#[must_use]
pub fn result_chars(envelope: &Value, is_error: bool, mode: ContentMode) -> u64 {
    let _ = (envelope, is_error, mode);
    0
}
