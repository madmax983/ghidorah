//! The `--select` output of `ghidorah call` (design Section 10.14, AC-185).
//!
//! The pointer uses the one dialect of [`ghidorah_json::pointer`]: RFC 6901 plus `*` for each
//! array item. Each selected value prints on its own line. A string prints without quotes.
//! A string with a line end prints as JSON text, so each value stays on one line.
//! Other values print as compact JSON.

use ghidorah_json::Value;
use ghidorah_json::pointer::Pointer;

/// Gives the output line of one selected value.
#[must_use]
pub fn value_line(value: &Value) -> String {
    match value {
        Value::String(text) if !text.contains(['\n', '\r']) => text.clone(),
        other => ghidorah_json::write(other),
    }
}

/// Gives the output lines of the values at `pointer` in `envelope`, in document order.
#[must_use]
pub fn lines(envelope: &Value, pointer: &Pointer) -> Vec<String> {
    ghidorah_json::pointer::select(envelope, pointer)
        .values
        .into_iter()
        .map(value_line)
        .collect()
}
