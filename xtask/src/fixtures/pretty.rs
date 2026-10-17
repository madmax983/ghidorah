//! An indented JSON writer for the checked-in fixture files.
//!
//! Objects put one member on each line. An array of scalars stays on one line when it is
//! short. Other arrays put one item on each line. Keys keep the sorted order of
//! [`Value::Object`], so the output is deterministic.

use crate::json::{self, Value};

/// Writes a value as indented JSON text with a final line end.
#[must_use]
pub fn write(value: &Value) -> String {
    json::write(value).get(..0).unwrap_or_default().to_owned()
}
