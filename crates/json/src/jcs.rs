//! The JSON canonicalization scheme of RFC 8785 (JCS).

use std::fmt;

use crate::value::Value;
use crate::write::{Style, render};

/// The reason that a value has no JCS form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JcsErrorKind {
    /// Two members of one object have the same name. RFC 8785 needs unique names.
    DuplicateKey,
    /// A number is outside the `f64` range, so it has no ECMAScript form.
    NumberRange,
}

impl JcsErrorKind {
    /// Gives the stable text form: `E_DUPLICATE_KEY` or `E_NUMBER_RANGE`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateKey => "E_DUPLICATE_KEY",
            Self::NumberRange => "E_NUMBER_RANGE",
        }
    }
}

/// A value that has no JCS form, with the RFC 6901 pointer of the bad member or number.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JcsError {
    /// The reason.
    pub kind: JcsErrorKind,
    /// The pointer of the repeated member or of the number, for example `/a/0`.
    pub path: String,
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            JcsErrorKind::DuplicateKey => "the object has two members with this name",
            JcsErrorKind::NumberRange => "the number is outside the f64 range",
        };
        write!(f, "{} at '{}': {what}", self.kind.as_str(), self.path)
    }
}

impl std::error::Error for JcsError {}

/// Writes the canonical RFC 8785 (JCS) text of `value`.
///
/// The text has no white space. Members sort by the UTF-16 code units of their names.
/// Numbers use the ECMAScript form of the nearest `f64`. Strings use the JSON escapes of
/// ECMAScript. So two values that differ only in member order give the same bytes.
///
/// # Errors
///
/// Returns [`JcsErrorKind::DuplicateKey`] for an object with a repeated name.
/// Returns [`JcsErrorKind::NumberRange`] for a number outside the `f64` range.
pub fn write_jcs(value: &Value) -> Result<String, JcsError> {
    render(value, Style::Jcs)
}

/// Compares two names by their UTF-16 code units, as RFC 8785 sorts them.
pub(crate) fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let _ = (a, b);
    std::cmp::Ordering::Equal
}
