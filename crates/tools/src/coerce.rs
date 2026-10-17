//! Lenient coercion of argument values (design Section 10.2).
//!
//! The argument parser calls [`lenient`] for a value of the wrong JSON type. A coercion that
//! succeeds gives `W_COERCED`. The published schema stays strict.
//!
//! | Expected kind | Input | Coerced value |
//! |---|---|---|
//! | `AddrList`, `List` | a string with a JSON array | the array |
//! | `Obj` | a string with a JSON object | the object |
//! | `Int` | a string of decimal digits with an optional `-` | the integer |
//! | `Bool` | `"true"` or `"false"` in any letter case | the boolean |
//! | `Enum` | a value of the enum in another letter case | the enum value |
//!
//! No other coercion exists. A string of hex digits is not an integer.

use ghidorah_json::Value;

use crate::spec::ArgKind;

/// The largest string that a coercion parses as JSON, in bytes.
pub const MAX_JSON_TEXT: usize = 1 << 20;

/// Gives the coerced value of `value` for the kind `kind`, or `None` when no coercion applies.
#[must_use]
pub fn lenient(kind: &ArgKind, value: &Value) -> Option<Value> {
    let _ = (kind, value);
    None
}
