//! The strict RFC 8259 parser.

use crate::error::{Code, JsonError};
use crate::value::Value;

/// The default nesting limit of [`Limits`] (design Section 13.6).
pub const DEFAULT_MAX_DEPTH: usize = 128;

/// The default byte limit of [`Limits`]: 16 MiB, the frame cap of the MCP reader.
pub const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;

/// The highest nesting depth that [`parse`] accepts, whatever the limit.
///
/// The drop, clone and compare code of [`Value`] uses one stack frame per level.
/// This ceiling keeps that code inside a small thread stack.
pub const DEPTH_CEILING: usize = 1024;

/// The resource limits of one parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The highest nesting depth of arrays and objects. A top scalar has depth 0.
    ///
    /// The parser uses the smaller of this value and [`DEPTH_CEILING`].
    pub max_depth: usize,
    /// The highest input length in bytes.
    pub max_bytes: usize,
}

impl Limits {
    /// The default limits: depth 128 and 16 MiB.
    pub const DEFAULT: Self = Self {
        max_depth: DEFAULT_MAX_DEPTH,
        max_bytes: DEFAULT_MAX_BYTES,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Parses `text` as one JSON value under `limits`.
///
/// The parser follows RFC 8259 strictly. It accepts only the four white space bytes.
/// It rejects a byte order mark, a lone surrogate escape and data after the value.
/// It keeps number lexemes, member order and repeated member names.
///
/// # Errors
///
/// Returns a [`JsonError`] with the [`Code`] and the byte offset of the first error.
/// [`Code::Depth`] gives the offset of the bracket or brace that is one level too deep.
/// [`Code::Size`] gives the offset `limits.max_bytes`.
pub fn parse(text: &str, limits: &Limits) -> Result<Value, JsonError> {
    let _ = (text, limits);
    Err(JsonError::new(Code::Syntax, 0))
}

/// Parses UTF-8 `bytes` as one JSON value under `limits`.
///
/// # Errors
///
/// Returns [`Code::Size`] when the input is longer than `limits.max_bytes`.
/// Returns [`Code::Utf8`] at the first byte that is not valid UTF-8.
/// Else returns the errors of [`parse`].
pub fn parse_bytes(bytes: &[u8], limits: &Limits) -> Result<Value, JsonError> {
    let _ = (bytes, limits);
    Err(JsonError::new(Code::Syntax, 0))
}
