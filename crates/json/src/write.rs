//! The writers: compact, pretty and the engine that JCS uses.

use crate::jcs::JcsError;
use crate::value::Value;

/// The output form of the writer engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Style {
    /// No white space, members in insertion order.
    Compact,
    /// Two spaces of indent per level, members in insertion order.
    Pretty,
    /// RFC 8785: no white space, members in UTF-16 order, ECMAScript numbers.
    Jcs,
}

/// Writes `value` as compact JSON text, with members in insertion order.
///
/// A number keeps its lexeme. A string escapes `"`, `\` and U+0000 to U+001F only.
/// The output never holds `NaN` or `inf`, and [`crate::parse`] reads it back as the same value.
#[must_use]
pub fn write(value: &Value) -> String {
    let _ = value;
    String::new()
}

/// Writes `value` as JSON text with two spaces of indent per level and a `": "` separator.
///
/// An empty array gives `[]`, and an empty object gives `{}`. The text has no final newline.
#[must_use]
pub fn write_pretty(value: &Value) -> String {
    let _ = value;
    String::new()
}

/// Writes `value` in `style`.
///
/// # Errors
///
/// Only [`Style::Jcs`] gives errors. See [`crate::write_jcs`].
pub(crate) fn render(value: &Value, style: Style) -> Result<String, JcsError> {
    let _ = (value, style);
    Ok(String::new())
}
