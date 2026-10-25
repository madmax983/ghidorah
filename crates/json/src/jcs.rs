//! The JSON canonicalization scheme of RFC 8785 (JCS).

use std::cmp::Ordering;
use std::fmt;

use crate::number::Number;
use crate::value::{Object, Value};
use crate::write::{Form, Members, render};

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
    render::<Jcs>(value).map_err(|(kind, path)| JcsError { kind, path })
}

/// The RFC 8785 form of the writer engine.
struct Jcs;

impl Form for Jcs {
    type Error = JcsErrorKind;
    const INDENT: Option<&'static str> = None;

    fn number(number: &Number, out: &mut String) -> Result<(), JcsErrorKind> {
        if let Some(plain) = number.jcs_plain() {
            out.push_str(plain);
            return Ok(());
        }
        let text = number.to_jcs().ok_or(JcsErrorKind::NumberRange)?;
        out.push_str(&text);
        Ok(())
    }

    fn members(object: &Object) -> Members<'_, JcsErrorKind> {
        let mut members: Vec<&(String, Value)> = object.members().iter().collect();
        members.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
        for pair in members.windows(2) {
            if let [(a, _), (b, _)] = pair
                && a == b
            {
                return Err((JcsErrorKind::DuplicateKey, a.as_str()));
            }
        }
        Ok(members)
    }
}

/// Compares two names by their UTF-16 code units, as RFC 8785 sorts them.
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}
