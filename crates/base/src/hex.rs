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
                write!(f, "The hex text has a byte that is not a digit at offset {offset}.")
            }
        }
    }
}

impl std::error::Error for HexError {}

/// Gives the lower case hex text of `bytes`, two digits per byte.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let _ = bytes;
    String::new()
}

/// Adds the lower case hex text of `bytes` to `out`.
pub fn encode_into(bytes: &[u8], out: &mut String) {
    let _ = (bytes, out);
}

/// Parses hex text with two digits per byte. Both letter cases are valid.
///
/// # Errors
///
/// Returns [`HexError::OddLength`] for an odd length and [`HexError::BadDigit`] for a byte
/// that is not a hex digit.
pub fn decode(text: &str) -> Result<Vec<u8>, HexError> {
    let _ = text;
    Ok(Vec::new())
}

/// Gives the text form of a 64-bit value: `0x` and lower case digits with no leading zeros.
///
/// Zero gives `0x0`.
#[must_use]
pub fn u64_text(value: u64) -> String {
    let _ = value;
    String::new()
}

/// Parses `0x` and 1 to 16 hex digits.
///
/// Gives `None` for any other text, for example a missing prefix, 17 digits or a sign.
#[must_use]
pub fn parse_u64(text: &str) -> Option<u64> {
    let _ = text;
    None
}

/// Parses 1 to 16 hex digits without a prefix.
#[must_use]
pub fn parse_digits(text: &str) -> Option<u64> {
    let _ = text;
    None
}
