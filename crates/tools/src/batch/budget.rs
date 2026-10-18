//! The budgets of a batch (design Section 11.5).
//!
//! | Budget | Rule |
//! |---|---|
//! | `max_chars` | The returned steps share it in step order. A step outside `return` gets the hard cap, so the batch does not trim it. |
//! | `max_steps` | Each step gets the fuel that the batch still has. |
//! | The result | The last fit drops data of returned steps from the end until the result fits. A step without its data keeps `omitted: { chars }`. |
//! | `resume` | The values of the references to completed steps, at most [`MAX_BINDINGS_CHARS`] characters. |

use ghidorah_json::{Object, Value};

use super::MAX_BINDINGS_CHARS;
use crate::budget::{Budget, HARD_MAX_CHARS};
use crate::content::{chars, cost};

/// The smallest budget of a returned step in characters.
pub const MIN_STEP_CHARS: u64 = 1_000;

/// The characters that the batch keeps for the members of its own envelope.
pub const WRAPPER_CHARS: u64 = 600;

/// The characters that the batch keeps for each step entry before the step runs.
pub const ENTRY_CHARS: u64 = 160;

/// Gives the size in characters of the compact JSON of `value`.
#[must_use]
pub fn size(value: &Value) -> u64 {
    chars(&ghidorah_json::write(value))
}

/// Gives the budget of a returned step: its share of the batch budget.
///
/// `used` is the size of the entries before the step, `later` the number of entries after
/// it, and `tool_max` the default budget of the tool.
#[must_use]
pub fn share(budget: &Budget, used: u64, later: usize, tool_max: u32) -> u64 {
    let later = u64::try_from(later).unwrap_or(u64::MAX);
    let room = budget
        .envelope_chars()
        .saturating_sub(WRAPPER_CHARS)
        .saturating_sub(used)
        .saturating_sub(later.saturating_mul(ENTRY_CHARS));
    room.clamp(MIN_STEP_CHARS, u64::from(tool_max).max(MIN_STEP_CHARS))
}

/// Gives the budget of a step outside `return`: the hard cap.
#[must_use]
pub const fn unreturned() -> u64 {
    HARD_MAX_CHARS as u64
}

/// Gives the result cost of `value` in the content mode of `budget`.
#[must_use]
pub fn result_cost(budget: &Budget, value: &Value) -> u64 {
    cost(&ghidorah_json::write(value), budget.mode)
}

/// Cuts step entries from the end until `fits` holds. Gives the number of cut entries.
///
/// The first pass drops `data` (it keeps `omitted: { chars }`), the second pass drops
/// `warnings`, `next` and `page.hint`, and the last pass keeps only `code`, `num` and
/// `message` of an error.
pub fn fit(entries: &mut [Value], fits: &mut dyn FnMut(&[Value]) -> bool) -> usize {
    let mut cut = 0usize;
    for pass in 0..3 {
        for i in (0..entries.len()).rev() {
            if fits(entries) {
                return cut;
            }
            let Some(Value::Object(entry)) = entries.get_mut(i) else {
                continue;
            };
            if shrink(entry, pass) {
                cut = cut.saturating_add(1);
            }
        }
    }
    cut
}

/// Shrinks one entry in pass `pass`. Gives `true` when the entry changed.
fn shrink(entry: &mut Object, pass: usize) -> bool {
    match pass {
        0 => match entry.remove("data") {
            Some(data) => {
                entry.push(
                    "omitted",
                    Value::object([("chars", Value::from(size(&data)))]),
                );
                true
            }
            None => false,
        },
        1 => {
            let a = entry.remove("warnings").is_some();
            let b = entry.remove("next").is_some();
            let c = entry
                .get_mut("page")
                .and_then(Value::as_object_mut)
                .and_then(|p| p.remove("hint"))
                .is_some();
            a || b || c
        }
        _ => {
            let Some(error) = entry.get("error").and_then(Value::as_object) else {
                return false;
            };
            let short: Object = ["code", "num", "message"]
                .iter()
                .filter_map(|k| error.get(k).map(|v| (*k, v.clone())))
                .collect();
            if short.len() == error.len() {
                return false;
            }
            let _ = entry.insert("error", Value::Object(short));
            true
        }
    }
}

/// Gives the resume bindings `[{ step, ptr, value }]`, or `None` when they are larger than
/// [`MAX_BINDINGS_CHARS`].
#[must_use]
pub fn bindings(list: Vec<(String, String, Value)>) -> Option<Value> {
    let mut out: Vec<Value> = Vec::new();
    for (step, ptr, value) in list {
        let seen = out.iter().any(|b| {
            b.get("step").and_then(Value::as_str) == Some(step.as_str())
                && b.get("ptr").and_then(Value::as_str) == Some(ptr.as_str())
        });
        if !seen {
            out.push(Value::object([
                ("step", Value::from(step)),
                ("ptr", Value::from(ptr)),
                ("value", value),
            ]));
        }
    }
    let value = Value::Array(out);
    (size(&value) <= MAX_BINDINGS_CHARS).then_some(value)
}
