//! The lexer of the C parser.
//!
//! The lexer reads the whole text first. It stops only at a limit. A character that starts
//! no token gives a [`Tok::Bad`] token, and the parser reports it at its place.

use ghidorah_base::DiagCode;

use super::diag::Fail;
use super::{MAX_IDENT, MAX_INPUT, MAX_TOKENS};

/// The punctuators, longest first.
const PUNCTS: [&str; 33] = [
    "...", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "[[", "(", ")", "[", "]", "{", "}", "*",
    ",", ";", ":", "=", "+", "-", "~", "!", "/", "%", "<", ">", "&", "^", "|", "?",
];

/// The kind of a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tok {
    /// An identifier or a keyword.
    Ident,
    /// An integer literal. `None` for a value above 128 bits.
    Int(Option<u128>),
    /// A punctuator.
    Punct(&'static str),
    /// `#`, the start of a preprocessor line.
    Hash,
    /// A character that starts no token, or an unterminated comment.
    Bad,
}

/// One token with its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Token {
    /// The kind.
    pub(crate) tok: Tok,
    /// The byte offset.
    pub(crate) byte: usize,
    /// The length in bytes.
    pub(crate) len: usize,
}

/// Gives the end of the run of bytes from `start` that match `keep`.
fn run_end(bytes: &[u8], start: usize, keep: impl Fn(u8) -> bool) -> usize {
    bytes
        .get(start..)
        .and_then(|rest| rest.iter().position(|b| !keep(*b)))
        .map_or(bytes.len(), |n| start.saturating_add(n))
}

/// Reads an integer literal: decimal, `0x` hex, `0b` binary or octal, with `u` and `l` suffixes.
///
/// Gives `None` for a bad literal, and [`Tok::Int`] with `None` for a value above 128 bits.
fn int_literal(text: &str) -> Option<Tok> {
    let digits_end = text.find(['u', 'U', 'l', 'L']).unwrap_or(text.len());
    let (digits, suffix) = text.split_at(digits_end);
    let suffix = suffix.to_ascii_lowercase();
    if !["", "u", "l", "ul", "lu", "ll", "ull", "llu"].contains(&suffix.as_str()) {
        return None;
    }
    let (radix, body) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, hex)
    } else if let Some(bin) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        (2, bin)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, digits.get(1..).unwrap_or(""))
    } else {
        (10, digits)
    };
    if body.is_empty() {
        return None;
    }
    let mut value: Option<u128> = Some(0);
    for c in body.chars() {
        let d = c.to_digit(radix)?;
        value = value
            .and_then(|v| v.checked_mul(u128::from(radix)))
            .and_then(|v| v.checked_add(u128::from(d)));
    }
    Some(Tok::Int(value))
}

/// Splits `text` into tokens.
///
/// # Errors
///
/// Returns a `E_LIMIT` failure for an input above [`MAX_INPUT`] bytes, more than
/// [`MAX_TOKENS`] tokens or an identifier above [`MAX_IDENT`] bytes.
pub(crate) fn lex(text: &str) -> Result<Vec<Token>, Fail> {
    if text.len() > MAX_INPUT {
        let mut at = MAX_INPUT;
        while !text.is_char_boundary(at) {
            at = at.saturating_sub(1);
        }
        return Err(Fail::new(DiagCode::Limit, at, 0)
            .hint("The text is longer than 1 MiB. Give a shorter text."));
    }
    let bytes = text.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0usize;
    while let Some(&c) = bytes.get(i) {
        let rest = text.get(i..).unwrap_or("");
        let (tok, len) = if c.is_ascii_whitespace() {
            i = i.saturating_add(1);
            continue;
        } else if rest.starts_with("//") {
            i = run_end(bytes, i, |b| b != b'\n');
            continue;
        } else if rest.starts_with("/*") {
            match rest.get(2..).and_then(|r| r.find("*/")) {
                Some(end) => {
                    i = i.saturating_add(end).saturating_add(4);
                    continue;
                }
                None => (Tok::Bad, 2),
            }
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let end = run_end(bytes, i, |b| b.is_ascii_alphanumeric() || b == b'_');
            let len = end.saturating_sub(i);
            if len > MAX_IDENT {
                return Err(Fail::new(DiagCode::Limit, i, len)
                    .hint("An identifier is longer than 1,024 bytes. Use a shorter name."));
            }
            (Tok::Ident, len)
        } else if c.is_ascii_digit() {
            let end = run_end(bytes, i, |b| b.is_ascii_alphanumeric() || b == b'_');
            let len = end.saturating_sub(i);
            (
                int_literal(rest.get(..len).unwrap_or("")).unwrap_or(Tok::Bad),
                len,
            )
        } else if c == b'#' {
            (Tok::Hash, 1)
        } else if let Some(p) = PUNCTS.iter().find(|p| rest.starts_with(**p)) {
            (Tok::Punct(p), p.len())
        } else {
            let len = rest.chars().next().map_or(1, char::len_utf8);
            (Tok::Bad, len)
        };
        if toks.len() >= MAX_TOKENS {
            return Err(Fail::new(DiagCode::Limit, i, len)
                .hint("The text has more than 200,000 tokens. Give a shorter text."));
        }
        toks.push(Token { tok, byte: i, len });
        if tok == Tok::Bad && rest.starts_with("/*") {
            break;
        }
        i = i.saturating_add(len);
    }
    Ok(toks)
}
