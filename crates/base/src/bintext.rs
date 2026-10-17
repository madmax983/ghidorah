//! `BinText`: the one carrier of binary text (design Section 10.16, ADR-0022).
//!
//! A [`BinText`] keeps the exact bytes from the binary. [`BinText::render`] gives the output
//! form, and [`BinText::to_json`] gives its one JSON shape:
//!
//! ```text
//! { "text": "..", "hex": "..", "len": N, "truncated": true, "src": "binary" }
//! ```
//!
//! `truncated` is present only when it is `true`.
//!
//! Escapes in `text`:
//!
//! | Input | Output |
//! |---|---|
//! | `\` | `\\` |
//! | C0 controls (U+0000 to U+001F) and DEL (U+007F) | `\x1b` |
//! | C1 controls (U+0080 to U+009F) | `\u{85}` |
//! | U+2028, U+2029 | `\u{2028}` |
//! | Bidi marks: U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069 | `\u{202e}` |
//! | Each byte of invalid UTF-8 | `\xff` |
//!
//! The text cap counts characters of the escaped text. It never cuts an escape.

/// The value of the `src` field.
pub const SRC: &str = "binary";

/// The hard cap of the text characters and of the hex bytes.
pub const HARD_CAP: usize = 4096;

/// The caps of one render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// The largest number of characters in `text`.
    pub text_chars: usize,
    /// The largest number of input bytes in `hex`.
    pub hex_bytes: usize,
}

impl Caps {
    /// The default caps: 256 characters and 512 bytes.
    pub const DEFAULT: Self = Self {
        text_chars: 256,
        hex_bytes: 512,
    };

    /// The caps of the `detailed` format: 4,096 characters and 4,096 bytes.
    pub const DETAILED: Self = Self {
        text_chars: HARD_CAP,
        hex_bytes: HARD_CAP,
    };

    /// Makes caps. Each value above [`HARD_CAP`] changes to [`HARD_CAP`].
    #[must_use]
    pub fn new(text_chars: usize, hex_bytes: usize) -> Self {
        let _ = (text_chars, hex_bytes);
        Self::DEFAULT
    }
}

impl Default for Caps {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The output form of a [`BinText`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The escaped text, cut at the text cap.
    pub text: String,
    /// The lower case hex of the bytes, cut at the hex cap.
    pub hex: String,
    /// The length of the bytes before any cut.
    pub len: usize,
    /// `true` when the text or the hex is cut.
    pub truncated: bool,
}

/// Text from a binary, kept as its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BinText {
    bytes: Vec<u8>,
}

impl BinText {
    /// Makes binary text from its bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Gives the exact bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Gives the number of bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Tells if the text has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Gives the text as `str` when the bytes are valid UTF-8.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }

    /// Gives the output form with the caps `caps`.
    #[must_use]
    pub fn render(&self, caps: Caps) -> Rendered {
        let _ = caps;
        Rendered {
            text: String::new(),
            hex: String::new(),
            len: 0,
            truncated: false,
        }
    }

    /// Gives the one JSON shape of the text with the caps `caps`.
    #[must_use]
    pub fn to_json(&self, caps: Caps) -> String {
        let _ = caps;
        String::new()
    }
}

impl From<&str> for BinText {
    fn from(text: &str) -> Self {
        Self::new(text.as_bytes())
    }
}

impl From<&[u8]> for BinText {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}
