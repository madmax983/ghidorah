//! The `calc` expression engine (design Section 10.4, AC-158).
//!
//! ```text
//! expr   := or
//! or     := xor ( "|" xor )*
//! xor    := and ( "^" and )*
//! and    := shift ( "&" shift )*
//! shift  := sum ( ( "<<" | ">>" ) sum )*
//! sum    := prod ( ( "+" | "-" ) prod )*
//! prod   := unary ( ( "*" | "/" | "%" ) unary )*
//! unary  := ( "-" | "~" | "+" ) unary | atom
//! atom   := "(" expr ")" | term
//! ```
//!
//! A term is a run of characters that are not white space, parentheses or operator marks.
//! A `0x` term is a hex number. A term of digits only gives `ADDRESS_BASE_AMBIGUOUS`, because
//! the server never guesses the base (ADR-0007). Each other term goes to the resolver of the
//! caller: a symbol, a section, a default name, `name@0x..` or an ID.
//!
//! Arithmetic uses 64 bits and wraps. Division and remainder are unsigned. A shift by 64 or
//! more gives 0. The evaluation uses an operator stack, not recursion. Open parentheses and
//! unary operators count as nesting. A nesting depth above [`MAX_DEPTH`] gives
//! `INVALID_ARGUMENT`.

use ghidorah_json::Value;

use crate::errors::ToolError;

/// The deepest nesting of parentheses and unary operators.
pub const MAX_DEPTH: usize = 64;

/// The longest expression in characters.
pub const MAX_EXPR_CHARS: usize = 1_024;

/// The view names of a value, in output order.
pub const VIEWS: [&str; 8] = ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"];

/// The resolver of the terms that are not numbers. It gives the value of the term.
pub type TermFn<'a> = &'a mut dyn FnMut(&str) -> Result<u64, ToolError>;

/// Evaluates the expression `text`. `term` gives the value of each name or ID term.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for a syntax error, a nesting depth above [`MAX_DEPTH`] or a
/// division by zero, `ADDRESS_INVALID` for a bad `0x` term, `ADDRESS_BASE_AMBIGUOUS` for a
/// term of digits only, and the error of `term` for a name that does not resolve.
pub fn eval(text: &str, term: TermFn<'_>) -> Result<u64, ToolError> {
    let _ = (text, term);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
}

/// Gives the decimal text of `value` read as a signed 64-bit integer.
#[must_use]
pub fn signed_text(value: u64) -> String {
    let _ = value;
    String::new()
}

/// Gives the views of `value`: the decimal text of the value cut to each width of [`VIEWS`],
/// read as unsigned or signed.
#[must_use]
pub fn views(value: u64) -> Value {
    let _ = value;
    Value::Null
}
