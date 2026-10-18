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
//! A pointer with a `*` segment gives the array of the values that it selects. A failed
//! test gives the actual value: the length for the length ops, else the value at `ptr`.

use std::cmp::Ordering;

use ghidorah_base::{Glob, hex};
use ghidorah_json::Value;
use ghidorah_json::pointer::{self, Pointer};

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

impl GuardOp {
    /// All ops in the order of [`OPS`].
    pub const ALL: [Self; 11] = [
        Self::Eq,
        Self::Ne,
        Self::Gt,
        Self::Ge,
        Self::Lt,
        Self::Le,
        Self::Contains,
        Self::Glob,
        Self::LenEq,
        Self::LenGt,
        Self::Exists,
    ];

    /// Gives the op of a name, or `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        OPS.iter()
            .position(|o| *o == name)
            .and_then(|i| Self::ALL.get(i).copied())
    }
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

/// Gives the integer of a number value, or the value of a 0x hex text.
fn ordinal(value: &Value) -> Option<i128> {
    match value {
        Value::Number(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from)),
        Value::String(text) => hex::parse_u64(text).map(i128::from),
        _ => None,
    }
}

/// Gives the length of an array, a text or an object.
fn length(value: &Value) -> Option<u64> {
    let n = match value {
        Value::Array(items) => items.len(),
        Value::String(text) => text.chars().count(),
        Value::Object(object) => object.len(),
        _ => return None,
    };
    u64::try_from(n).ok()
}

impl Guard {
    /// Parses one guard object `{ ptr, op, value? }`.
    ///
    /// # Errors
    ///
    /// Returns the text of `details.expected` when the object has no valid pointer, no known
    /// op, or no value for an op that needs one.
    pub fn parse(object: &Value) -> Result<Self, String> {
        let expected = "a guard { ptr, op, value } with a JSON pointer and an op of the list";
        let fail = || expected.to_owned();
        let Value::Object(members) = object else {
            return Err(fail());
        };
        let ptr = members
            .get("ptr")
            .and_then(Value::as_str)
            .ok_or_else(fail)?;
        let parsed = pointer::parse(ptr).map_err(|_| fail())?;
        let op = members
            .get("op")
            .and_then(Value::as_str)
            .and_then(GuardOp::parse)
            .ok_or_else(fail)?;
        let value = match (op, members.get("value")) {
            (GuardOp::Exists, None) => Value::Bool(true),
            (GuardOp::Exists, Some(v)) if v.as_bool().is_none() => return Err(fail()),
            (GuardOp::LenEq | GuardOp::LenGt, Some(v)) if v.as_u64().is_none() => {
                return Err(fail());
            }
            (GuardOp::Glob, Some(v)) if v.as_str().is_none_or(|t| Glob::new(t).is_err()) => {
                return Err(fail());
            }
            (_, Some(v)) => v.clone(),
            (_, None) => return Err(fail()),
        };
        Ok(Self {
            ptr: ptr.to_owned(),
            pointer: parsed,
            op,
            value,
        })
    }

    /// Gives the value at the pointer: the array of the selected values for a `*` pointer.
    fn actual(&self, envelope: &Value) -> Option<Value> {
        if self.pointer.has_star() {
            let selection = pointer::select(envelope, &self.pointer);
            return Some(Value::Array(
                selection.values.into_iter().cloned().collect(),
            ));
        }
        pointer::get(envelope, &self.pointer).cloned()
    }

    /// Tests the guard on `envelope`.
    ///
    /// # Errors
    ///
    /// Returns the actual value when the test fails: the length for `len_eq` and `len_gt`,
    /// else the value at the pointer. A missing path gives `null`.
    pub fn check(&self, envelope: &Value) -> Result<(), Value> {
        let found = self.actual(envelope);
        let actual = found.clone().unwrap_or(Value::Null);
        let order = || match (found.as_ref().and_then(ordinal), ordinal(&self.value)) {
            (Some(a), Some(b)) => Some(a.cmp(&b)),
            _ => None,
        };
        let pass = match self.op {
            GuardOp::Exists => found.is_some() == self.value.as_bool().unwrap_or(true),
            GuardOp::Eq => found.as_ref() == Some(&self.value),
            GuardOp::Ne => found.is_some() && found.as_ref() != Some(&self.value),
            GuardOp::Gt => order() == Some(Ordering::Greater),
            GuardOp::Ge => order().is_some_and(Ordering::is_ge),
            GuardOp::Lt => order() == Some(Ordering::Less),
            GuardOp::Le => order().is_some_and(Ordering::is_le),
            GuardOp::Contains => match (&actual, &self.value) {
                (Value::String(text), Value::String(part)) => text.contains(part.as_str()),
                (Value::Array(items), want) => items.contains(want),
                (Value::Object(object), Value::String(key)) => object.contains_key(key),
                _ => false,
            },
            GuardOp::Glob => {
                let glob = self.value.as_str().and_then(|t| Glob::new(t).ok());
                match (actual.as_str(), glob) {
                    (Some(text), Some(glob)) => glob.matches(text),
                    _ => false,
                }
            }
            GuardOp::LenEq | GuardOp::LenGt => {
                let len = length(&actual);
                let want = self.value.as_u64();
                let pass = match (len, want, self.op) {
                    (Some(n), Some(w), GuardOp::LenEq) => n == w,
                    (Some(n), Some(w), _) => n > w,
                    _ => false,
                };
                if !pass {
                    return Err(len.map_or(Value::Null, Value::from));
                }
                true
            }
        };
        if pass { Ok(()) } else { Err(actual) }
    }
}
