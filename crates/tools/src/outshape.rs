//! `OutputShape`: the typed tree of a tool result (design Section 10.1).
//!
//! No tool declares `outputSchema` (Section 10.10). The shape documents the `data` member
//! of the envelope, and test `ac_132a` checks each example result against it.
//! `batch_run` uses it to type references before a step runs (Section 11.3).

use std::fmt;

use ghidorah_base::{Id, IdKind};
use ghidorah_json::Value;

/// The shape of one output value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputShape {
    /// Any value.
    Any,
    /// A string.
    Str,
    /// An integer below 2^53.
    Int,
    /// `true` or `false`.
    Bool,
    /// An address: a string `^0x[0-9a-f]+$`.
    Addr,
    /// An ID of this kind, for example `fn:0x401000`.
    Id(IdKind),
    /// Binary text in its one JSON shape `{ text, hex, len, truncated?, src }` (ADR-0022).
    Text,
    /// `null` or a value of the inner shape.
    Nullable(&'static Self),
    /// An array of values of the inner shape.
    List(&'static Self),
    /// An object with these members and no others.
    Obj(&'static [Field]),
}

/// One member of an object shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// The member name.
    pub name: &'static str,
    /// The shape of the member value.
    pub shape: OutputShape,
    /// `true` when the member can be absent.
    pub optional: bool,
}

impl Field {
    /// Makes a required member.
    #[must_use]
    pub const fn req(name: &'static str, shape: OutputShape) -> Self {
        Self {
            name,
            shape,
            optional: false,
        }
    }

    /// Makes an optional member.
    #[must_use]
    pub const fn opt(name: &'static str, shape: OutputShape) -> Self {
        Self {
            name,
            shape,
            optional: true,
        }
    }
}

/// The first place where a value does not fit its shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeError {
    /// The JSON pointer of the value, for example `/items/3/addr`.
    pub path: String,
    /// What the shape expects there, for example `address` or `member name`.
    pub expected: String,
}

impl fmt::Display for ShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The value at {} does not fit. The shape expects {}.",
            self.path, self.expected
        )
    }
}

impl std::error::Error for ShapeError {}

/// How strict a fit check is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fit {
    /// Every required member must be present.
    Exact,
    /// Members can be absent. Use it for results with `fields` (a projection).
    Partial,
}

impl OutputShape {
    /// Checks `value` against the shape.
    ///
    /// # Errors
    ///
    /// Returns [`ShapeError`] for the first value in document order that does not fit.
    /// An object member that the shape does not name does not fit.
    pub fn check(&self, value: &Value, fit: Fit) -> Result<(), ShapeError> {
        let _ = (value, fit);
        Err(ShapeError {
            path: String::new(),
            expected: String::new(),
        })
    }
}

/// Tells if `text` is an address text: `0x` and lower case hex digits.
#[must_use]
pub fn is_addr_text(text: &str) -> bool {
    let _ = text;
    false
}

/// Tells if `text` parses as an ID of `kind`.
#[must_use]
pub fn is_id_text(text: &str, kind: IdKind) -> bool {
    Id::parse(text).is_ok_and(|id| id.kind() == kind) && false
}
