//! Hex text (ADR-0007).
//!
//! Output writes each 64-bit value as lower case `0x` hex with no leading zeros.
//! Input reads `0x` and 1 to 16 hex digits in either letter case.

use std::fmt;

/// The largest number of hex digits in a 64-bit value.
pub const MAX_U64_DIGITS: usize = 16;

/// An error of [`decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// The text has an odd number of digits.
    OddLength {
        /// The length of the text in bytes.
        len: usize,
    },
    /// The byte at `offset` is not a hex digit.
    BadDigit {
        /// The byte offset in the text.
        offset: usize,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength { len } => write!(f, "The hex text has an odd length of {len}."),
            Self::BadDigit { offset } => {
                write!(
                    f,
                    "The hex text has a byte that is not a digit at offset {offset}."
                )
            }
        }
    }
}

impl std::error::Error for HexError {}

/// The lower case hex digits.
const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Gives the lower case hex text of `bytes`, two digits per byte.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    encode_into(bytes, &mut out);
    out
}

/// Adds the lower case hex text of `bytes` to `out`.
pub fn encode_into(bytes: &[u8], out: &mut String) {
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
}

/// Gives the value of one hex digit in either letter case.
const fn digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parses hex text with two digits per byte. Both letter cases are valid.
///
/// # Errors
///
/// Returns [`HexError::OddLength`] for an odd length and [`HexError::BadDigit`] for a byte
/// that is not a hex digit.
pub fn decode(text: &str) -> Result<Vec<u8>, HexError> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(HexError::OddLength { len: bytes.len() });
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        if let [hi, lo] = *pair {
            let offset = i * 2;
            let hi = digit(hi).ok_or(HexError::BadDigit { offset })?;
            let lo = digit(lo).ok_or(HexError::BadDigit { offset: offset + 1 })?;
            out.push((hi << 4) | lo);
        }
    }
    Ok(out)
}

/// Gives the text form of a 64-bit value: `0x` and lower case digits with no leading zeros.
///
/// Zero gives `0x0`.
#[must_use]
pub fn u64_text(value: u64) -> String {
    format!("{value:#x}")
}

/// Parses `0x` and 1 to 16 hex digits.
///
/// Gives `None` for any other text, for example a missing prefix, 17 digits or a sign.
#[must_use]
pub fn parse_u64(text: &str) -> Option<u64> {
    parse_digits(text.strip_prefix("0x")?)
}

/// Parses 1 to 16 hex digits without a prefix.
#[must_use]
pub fn parse_digits(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > MAX_U64_DIGITS {
        return None;
    }
    text.bytes()
        .try_fold(0u64, |acc, b| Some((acc << 4) | u64::from(digit(b)?)))
}
