//! Strict RFC 8259 JSON for ghidorah.
//!
//! The crate is a leaf. It has no workspace dependencies and uses the standard library only.
//!
//! Parts:
//!
//! - [`Value`]: a JSON value. An [`Object`] keeps its members in insertion order.
//!   A [`Number`] keeps its raw lexeme, so a large integer does not lose bits.
//! - [`parse`] and [`parse_bytes`]: a strict parser with a depth limit and a byte limit.
//!   An error gives a [`Code`] and a byte offset ([`JsonError`]).
//! - [`write()`] and [`write_pretty`]: writers that keep the member order.
//! - [`write_jcs`]: the canonical form of RFC 8785 (JCS) for hashes and golden files.
//! - [`mod@pointer`]: the one pointer dialect of ghidorah, RFC 6901 plus a `*` segment.
//! - [`ToJson`], [`FromJson`] and [`json_record!`]: codecs for record structs.
//!
//! The parser, the writers and [`pointer::select`] use no recursion, so deep input cannot
//! overflow the stack. The parser also keeps each value at most [`DEPTH_CEILING`] levels deep.

#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod error;
mod jcs;
mod number;
mod parse;
pub mod pointer;
mod record;
mod value;
mod write;

pub use error::{Code, JsonError};
pub use jcs::{JcsError, JcsErrorKind, write_jcs};
pub use number::Number;
pub use parse::{DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH, DEPTH_CEILING, Limits, parse, parse_bytes};
pub use record::{DecodeError, DecodeKind, Fields, FromJson, ToJson, field_key};
pub use value::{Object, Value};
pub use write::{write, write_pretty};
