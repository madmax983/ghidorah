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

use crate::hex;

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
        Self {
            text_chars: text_chars.min(HARD_CAP),
            hex_bytes: hex_bytes.min(HARD_CAP),
        }
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
        let (text, text_cut) = escape_capped(&self.bytes, caps.text_chars);
        let shown = self.bytes.get(..caps.hex_bytes).unwrap_or(&self.bytes);
        Rendered {
            text,
            hex: hex::encode(shown),
            len: self.bytes.len(),
            truncated: text_cut || shown.len() < self.bytes.len(),
        }
    }

    /// Gives the one JSON shape of the text with the caps `caps`.
    #[must_use]
    pub fn to_json(&self, caps: Caps) -> String {
        let r = self.render(caps);
        let mut out = String::with_capacity(r.text.len() + r.hex.len() + 64);
        out.push_str("{\"text\":\"");
        for c in r.text.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                _ => out.push(c),
            }
        }
        out.push_str("\",\"hex\":\"");
        out.push_str(&r.hex);
        out.push_str("\",\"len\":");
        out.push_str(&r.len.to_string());
        if r.truncated {
            out.push_str(",\"truncated\":true");
        }
        out.push_str(",\"src\":\"");
        out.push_str(SRC);
        out.push_str("\"}");
        out
    }
}

/// Tells if `c` is a bidi mark that the text escapes.
const fn is_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

/// Gives the escape of one character, or `None` when the character needs no escape.
fn escape_char(c: char) -> Option<String> {
    match c {
        '\\' => Some("\\\\".to_string()),
        '\u{0}'..='\u{1f}' | '\u{7f}' => Some(format!("\\x{:02x}", u32::from(c))),
        '\u{80}'..='\u{9f}' | '\u{2028}' | '\u{2029}' => Some(format!("\\u{{{:x}}}", u32::from(c))),
        _ if is_bidi(c) => Some(format!("\\u{{{:x}}}", u32::from(c))),
        _ => None,
    }
}

/// Escapes `bytes` and stops before the text passes `cap` characters.
///
/// Gives the text and `true` when the text does not hold all bytes.
fn escape_capped(bytes: &[u8], cap: usize) -> (String, bool) {
    let mut text = Capped {
        out: String::new(),
        chars: 0,
        cap,
    };
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            let fits = match escape_char(c) {
                Some(esc) => text.push(&esc),
                None => text.push(c.encode_utf8(&mut [0u8; 4])),
            };
            if !fits {
                return (text.out, true);
            }
        }
        for b in chunk.invalid() {
            if !text.push(&format!("\\x{b:02x}")) {
                return (text.out, true);
            }
        }
    }
    (text.out, false)
}

/// Text with a cap on its number of characters.
struct Capped {
    out: String,
    chars: usize,
    cap: usize,
}

impl Capped {
    /// Adds `piece` when it fits under the cap. Gives `false` when it does not fit.
    fn push(&mut self, piece: &str) -> bool {
        let width = piece.chars().count();
        match self.chars.checked_add(width) {
            Some(total) if total <= self.cap => {
                self.out.push_str(piece);
                self.chars = total;
                true
            }
            _ => false,
        }
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
