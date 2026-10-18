//! The guards of a batch step (design Section 11.2).
//!
//! An `expect` guard `{ ptr, op, value? }` tests the step envelope at a pointer of the one
//! dialect. The eval harness uses the same grammar for its answer checks.
//!
//! | Op | Passes when |
//! |---|---|
//! | `eq`, `ne` | the value at `ptr` is equal, or not equal, to `value` |
//! | `gt`, `ge`, `lt`, `le` | both are numbers or both are 0x hex texts, and the order holds |
//! | `contains` | a text holds the text `value`, an array holds an item equal to `value`, or an object has the member `value` |
//! | `glob` | the text at `ptr` matches the glob `value` |
//! | `len_eq`, `len_gt` | the length of the array, text or object at `ptr` is equal to, or greater than, `value` |
//! | `exists` | the pointer gives a value (`value: false` asks for no value) |
//!
//! A pointer with a `*` segment gives the array of the values that it selects.

use ghidorah_json::Value;
use ghidorah_json::pointer::Pointer;

/// The guard ops in schema order.
pub const OPS: [&str; 11] = [
    "eq", "ne", "gt", "ge", "lt", "le", "contains", "glob", "len_eq", "len_gt", "exists",
];

/// The test of one guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuardOp {
    /// `eq`.
    Eq,
    /// `ne`.
    Ne,
    /// `gt`.
    Gt,
    /// `ge`.
    Ge,
    /// `lt`.
    Lt,
    /// `le`.
    Le,
    /// `contains`.
    Contains,
    /// `glob`.
    Glob,
    /// `len_eq`.
    LenEq,
    /// `len_gt`.
    LenGt,
    /// `exists`.
    Exists,
}

/// One parsed guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guard {
    /// The pointer text.
    pub ptr: String,
    /// The parsed pointer.
    pub pointer: Pointer,
    /// The op.
    pub op: GuardOp,
    /// The value of the test. `exists` uses `true` when the guard has no value.
    pub value: Value,
}

impl Guard {
    /// Parses one guard object `{ ptr, op, value? }`.
    ///
    /// # Errors
    ///
    /// Returns the text of `details.expected` when the object has no valid pointer, no known
    /// op, or no value for an op that needs one.
    pub fn parse(object: &Value) -> Result<Self, String> {
        let _ = object;
        Err("a guard".to_owned())
    }

    /// Tests the guard on `envelope`.
    ///
    /// # Errors
    ///
    /// Returns the actual value at the pointer when the test fails. A missing path gives
    /// `null`.
    pub fn check(&self, envelope: &Value) -> Result<(), Value> {
        let _ = envelope;
        Err(Value::Null)
    }
}
