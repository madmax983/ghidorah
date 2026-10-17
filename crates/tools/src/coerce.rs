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

use ghidorah_json::{Limits, Number, Value};

use crate::spec::ArgKind;

/// The largest string that a coercion parses as JSON, in bytes.
pub const MAX_JSON_TEXT: usize = 1 << 20;

/// Gives the coerced value of `value` for the kind `kind`, or `None` when no coercion applies.
#[must_use]
pub fn lenient(kind: &ArgKind, value: &Value) -> Option<Value> {
    let Value::String(text) = value else {
        return None;
    };
    match kind {
        ArgKind::AddrList(_) | ArgKind::List(..) => {
            json_text(text).filter(|v| v.as_array().is_some())
        }
        ArgKind::Obj(_) => json_text(text).filter(|v| v.as_object().is_some()),
        ArgKind::Int { .. } => integer(text),
        ArgKind::Bool => match text.to_ascii_lowercase().as_str() {
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        },
        ArgKind::Enum(values) => values
            .iter()
            .find(|v| v.eq_ignore_ascii_case(text))
            .map(|v| Value::from(*v)),
        ArgKind::Addr | ArgKind::Id(_) | ArgKind::Str(_) | ArgKind::Json => None,
    }
}

/// Parses a string that holds JSON text.
fn json_text(text: &str) -> Option<Value> {
    if text.len() > MAX_JSON_TEXT {
        return None;
    }
    ghidorah_json::parse(text, &Limits::DEFAULT).ok()
}

/// Parses decimal digits with an optional leading `-` as a JSON integer.
fn integer(text: &str) -> Option<Value> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || digits.len() > 20 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Number::parse(text).ok().map(Value::Number)
}
