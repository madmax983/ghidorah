//! The quoted form of a name part in an ID (ADR-0008, amendment 2026-10-20).
//!
//! A name part shows in the quoted form when it holds a character that
//! [`BinText`](crate::BinText) escapes, or when it starts with a double quote. The quoted form
//! is a double quote, the name with escapes and a closing double quote. Every other name shows
//! its exact text.
//!
//! | Character | Escape |
//! |---|---|
//! | `\` | `\\` |
//! | `"` | `\"` |
//! | C0 controls, DEL and C1 controls (U+0000 to U+001F, U+007F to U+009F) | `\x1b` |
//! | Each other character that `BinText` escapes | `\u{202e}` |
//!
//! The parser undoes the escapes. It also accepts the quoted form of a name that needs no
//! quotes.

use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::str::CharIndices;

use crate::bintext::escapes;

/// Tells if `name` shows in the quoted form.
pub(crate) fn needs_quotes(name: &str) -> bool {
    name.starts_with('"') || name.chars().any(escapes)
}

/// One name part for `Display`: the exact text or the quoted form.
pub(crate) struct Name<'a>(pub(crate) &'a str);

impl fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !needs_quotes(self.0) {
            return f.write_str(self.0);
        }
        f.write_str("\"")?;
        for c in self.0.chars() {
            match c {
                '\\' => f.write_str("\\\\")?,
                '"' => f.write_str("\\\"")?,
                '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => write!(f, "\\x{:02x}", u32::from(c))?,
                _ if escapes(c) => write!(f, "\\u{{{:x}}}", u32::from(c))?,
                _ => f.write_char(c)?,
            }
        }
        f.write_str("\"")
    }
}

/// Reads the quoted name at the start of `text`.
///
/// Gives the name and the text after the closing quote. A bad quoted form gives `None`.
pub(crate) fn unquote(text: &str) -> Option<(String, &str)> {
    let mut chars = text.char_indices();
    if chars.next()?.1 != '"' {
        return None;
    }
    let mut out = String::new();
    // Each turn reads at least one character of `text`, so the loop ends.
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Some((out, text.get(at.checked_add(1)?..)?)),
            '\\' => out.push(escape(&mut chars)?),
            _ => out.push(c),
        }
    }
    None
}

/// Reads a name part that fills all of `text`: the quoted form or the exact text.
pub(crate) fn whole_name(text: &str) -> Option<Cow<'_, str>> {
    if text.starts_with('"') {
        match unquote(text)? {
            (name, "") => Some(Cow::Owned(name)),
            _ => None,
        }
    } else {
        Some(Cow::Borrowed(text))
    }
}

/// Reads one escape after its backslash.
fn escape(chars: &mut CharIndices<'_>) -> Option<char> {
    match chars.next()?.1 {
        '\\' => Some('\\'),
        '"' => Some('"'),
        'x' => {
            let high = chars.next()?.1.to_digit(16)?;
            let low = chars.next()?.1.to_digit(16)?;
            char::from_u32((high << 4) | low)
        }
        'u' => {
            if chars.next()?.1 != '{' {
                return None;
            }
            let mut value: u32 = 0;
            // A code point has at most 6 hex digits, and the closing brace ends the escape.
            for count in 0..=6 {
                let c = chars.next()?.1;
                if c == '}' {
                    return if count == 0 {
                        None
                    } else {
                        char::from_u32(value)
                    };
                }
                value = value.checked_mul(16)?.checked_add(c.to_digit(16)?)?;
            }
            None
        }
        _ => None,
    }
}
