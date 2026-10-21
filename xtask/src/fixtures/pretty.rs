//! An indented JSON writer for the checked-in fixture files.
//!
//! Objects put one member on each line. An array of scalars stays on one line when it is
//! short. Other arrays put one item on each line. Keys keep the sorted order of
//! [`Value::Object`], so the output is deterministic.

use crate::json::{self, Value};

/// The longest one-line array, in bytes.
const LINE: usize = 100;

/// Writes a value as indented JSON text with a final line end.
#[must_use]
pub fn write(value: &Value) -> String {
    let mut out = String::new();
    write_into(&mut out, value, 0);
    out.push('\n');
    out
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn is_scalar(value: &Value) -> bool {
    !matches!(value, Value::Array(_) | Value::Object(_))
}

fn write_into(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Array(items) if items.is_empty() => out.push_str("[]"),
        Value::Object(members) if members.is_empty() => out.push_str("{}"),
        Value::Array(items) => {
            let flat = json::write(value);
            if items.iter().all(is_scalar) && flat.len() <= LINE {
                out.push_str(&flat);
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                indent(out, depth + 1);
                write_into(out, item, depth + 1);
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, depth);
            out.push(']');
        }
        Value::Object(members) => {
            out.push_str("{\n");
            for (i, (key, item)) in members.iter().enumerate() {
                indent(out, depth + 1);
                out.push_str(&json::write(&Value::from(key.as_str())));
                out.push_str(": ");
                write_into(out, item, depth + 1);
                if i + 1 < members.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, depth);
            out.push('}');
        }
        scalar => out.push_str(&json::write(scalar)),
    }
}
