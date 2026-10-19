//! Answer sources, derive steps and answer checks (design Section 12.2).
//!
//! A [`Source`] names a turn and a pointer of the one pointer dialect (RFC 6901 plus `*`).
//! Its `steps` are the reasoning of the agent over the response: filter a list, pick a
//! member, count lines, decode bytes. Each step is an object with an `op` member:
//!
//! | Op | Input | Members | Output |
//! |---|---|---|---|
//! | `where` | list of objects | `ptr` and one of `eq`, `ne`, `glob`, `iglob`, `has` | the items that match |
//! | `same` | list of objects | `a`, `b` | the items whose values at `a` and `b` are equal |
//! | `pick` | list | `ptr` | the value at `ptr` of each item |
//! | `first`, `count`, `unique`, `sort` | list | - | the first item, the count, the list without repeats, the sorted list |
//! | `lines` | text | - | the trimmed lines that are not blank |
//! | `split` | text | `on` | the parts of the text |
//! | `drop`, `take` | list | `count` | the list without its first items, or only its first items |
//! | `grep` | list of texts | `glob`, `icase`?, `not`? | the texts that match, or with `not` the texts that do not match |
//! | `after`, `before` | text or texts | `text` | the part after or before the first `text` |
//! | `trim_prefix`, `trim_suffix` | text or texts | `text` | the text without the prefix or suffix |
//! | `trim`, `token`, `int` | text or texts | - | the text without spaces, its first word, its integer value |
//! | `xor` | hex text | `key` (a source), `var`? | the text of the bytes XOR the key of each index |
//!
//! The `xor` key is a number or a C expression in the variable `var` (default `i`), which
//! [`crate::expr`] evaluates for each byte index.

use ghidorah_json::pointer;
use ghidorah_json::{Number, Value};

use crate::expr;
use crate::glob;

/// The largest number of derive steps of a source.
pub const MAX_STEPS: usize = 16;

/// The largest number of bytes that `xor` decodes.
pub const MAX_XOR: usize = 4096;

/// The source of a value: a turn, a pointer and derive steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The index of the turn whose response holds the value.
    pub turn: usize,
    /// The pointer into the response envelope.
    pub ptr: String,
    /// The derive steps, in order.
    pub steps: Vec<Value>,
}

/// Parses a source object `{ turn | $turn, ptr, steps? }`.
///
/// # Errors
///
/// Returns a message when a member is missing, the pointer does not parse or a step has no
/// `op`.
pub fn parse_source(v: &Value) -> Result<Source, String> {
    let turn = v
        .get("turn")
        .or_else(|| v.get("$turn"))
        .and_then(Value::as_u64)
        .and_then(|t| usize::try_from(t).ok())
        .ok_or("a source has no `turn`")?;
    let ptr = v
        .get("ptr")
        .and_then(Value::as_str)
        .ok_or("a source has no `ptr`")?;
    pointer::parse(ptr).map_err(|e| format!("the pointer {ptr} does not parse: {e}"))?;
    let steps = v
        .get("steps")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .to_vec();
    if steps.len() > MAX_STEPS {
        return Err("a source has more than 16 steps".to_owned());
    }
    for step in &steps {
        let op = step
            .get("op")
            .and_then(Value::as_str)
            .ok_or("a step has no `op`")?;
        if !OPS.contains(&op) {
            return Err(format!("the step op {op} is not known"));
        }
        if let Some(key) = step.get("key") {
            parse_source(key)?;
        }
    }
    Ok(Source {
        turn,
        ptr: ptr.to_owned(),
        steps,
    })
}

/// The step ops.
pub const OPS: &[&str] = &[
    "where",
    "same",
    "pick",
    "first",
    "count",
    "unique",
    "sort",
    "lines",
    "split",
    "drop",
    "take",
    "grep",
    "after",
    "before",
    "trim_prefix",
    "trim_suffix",
    "trim",
    "token",
    "int",
    "xor",
];

/// Gives the value at `ptr` of `root`. A `*` pointer gives a list.
///
/// # Errors
///
/// Returns a message when the pointer does not parse or a path is missing.
pub fn select(root: &Value, ptr: &str) -> Result<Value, String> {
    let p = pointer::parse(ptr).map_err(|e| format!("the pointer {ptr} does not parse: {e}"))?;
    if p.has_star() {
        let sel = pointer::select(root, &p);
        if !sel.is_complete() {
            return Err(format!(
                "the path {} is missing",
                sel.first_missing.unwrap_or_default()
            ));
        }
        return Ok(Value::Array(sel.values.into_iter().cloned().collect()));
    }
    pointer::get(root, &p)
        .cloned()
        .ok_or_else(|| format!("the path {ptr} is missing"))
}

/// Gives the value of `src` over the responses of a run.
///
/// # Errors
///
/// Returns a message when the turn has no response, a path is missing or a step fails.
pub fn extract(responses: &[Value], src: &Source) -> Result<Value, String> {
    let root = responses
        .get(src.turn)
        .ok_or_else(|| format!("the turn {} has no response", src.turn))?;
    let mut value = select(root, &src.ptr)?;
    for step in &src.steps {
        value = apply(value, step, responses)?;
    }
    Ok(value)
}

fn list(value: Value, op: &str) -> Result<Vec<Value>, String> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(format!("the step {op} needs a list")),
    }
}

fn text_arg<'a>(step: &'a Value, key: &str) -> Result<&'a str, String> {
    step.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("the step has no text `{key}`"))
}

/// Applies a text function to a text, or to each text of a list.
fn map_text(value: Value, f: &dyn Fn(&str) -> Result<Value, String>) -> Result<Value, String> {
    match value {
        Value::String(s) => f(&s),
        Value::Array(items) => items
            .into_iter()
            .map(|item| map_text(item, f))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        other => Err(format!("a text step needs a text, not {other}")),
    }
}

/// Gives the text form of a scalar: the string itself, or the JSON text.
#[must_use]
pub fn text_of(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Tells if two values are equal. Numbers compare by their integer value when they have one.
#[must_use]
pub fn json_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(l), Value::Number(r)) => match (l.as_i64(), r.as_i64()) {
            (Some(li), Some(ri)) => li == ri,
            _ => l == r,
        },
        (Value::Array(l), Value::Array(r)) => {
            l.len() == r.len() && l.iter().zip(r).all(|(li, ri)| json_eq(li, ri))
        }
        _ => left == right,
    }
}

fn matches_where(item: &Value, step: &Value) -> Result<bool, String> {
    let at = select(item, text_arg(step, "ptr")?).unwrap_or(Value::Null);
    if let Some(v) = step.get("eq") {
        return Ok(json_eq(&at, v));
    }
    if let Some(v) = step.get("ne") {
        return Ok(!json_eq(&at, v));
    }
    if let Some(g) = step.get("glob").and_then(Value::as_str) {
        return Ok(glob::matches(g, &text_of(&at), false));
    }
    if let Some(g) = step.get("iglob").and_then(Value::as_str) {
        return Ok(glob::matches(g, &text_of(&at), true));
    }
    if let Some(v) = step.get("has") {
        return Ok(at
            .as_array()
            .is_some_and(|items| items.iter().any(|i| json_eq(i, v))));
    }
    Err("the step where needs eq, ne, glob, iglob or has".to_owned())
}

/// Parses an integer text: `0x` hex or decimal.
#[must_use]
pub fn parse_int(text: &str) -> Option<u64> {
    let t = text.trim();
    t.strip_prefix("0x")
        .map_or_else(|| t.parse().ok(), |hex| u64::from_str_radix(hex, 16).ok())
}

fn token(text: &str) -> Value {
    let t = text.trim_start();
    let end = t
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(t.len());
    Value::from(&t[..end])
}

fn xor(value: &Value, step: &Value, responses: &[Value]) -> Result<Value, String> {
    let hex = value.as_str().ok_or("the step xor needs a hex text")?;
    if hex.len() % 2 != 0 || hex.len() > MAX_XOR * 2 {
        return Err("the step xor needs an even hex text of at most 4096 bytes".to_owned());
    }
    let key_src = step.get("key").ok_or("the step xor has no `key`")?;
    let key = extract(responses, &parse_source(key_src)?)?;
    let var = step.get("var").and_then(Value::as_str).unwrap_or("i");
    let mut out = Vec::new();
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
        let byte = u8::from_str_radix(text, 16).map_err(|e| e.to_string())?;
        let index = u64::try_from(i).unwrap_or(u64::MAX);
        let k = match &key {
            Value::Number(n) => n.as_u64().ok_or("the xor key is not an integer")?,
            Value::String(s) => expr::eval(s, var, index)?,
            _ => return Err("the xor key is not a number or an expression".to_owned()),
        };
        out.push(byte ^ u8::try_from(k & 0xff).unwrap_or(0));
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    String::from_utf8(out)
        .map(Value::from)
        .map_err(|_| "the decoded bytes are not UTF-8".to_owned())
}

/// Applies one step to `value`.
///
/// # Errors
///
/// Returns a message when the step does not fit its input.
pub fn apply(value: Value, step: &Value, responses: &[Value]) -> Result<Value, String> {
    let op = step.get("op").and_then(Value::as_str).unwrap_or_default();
    match op {
        "xor" => xor(&value, step, responses),
        "lines" | "split" | "after" | "before" | "trim_prefix" | "trim_suffix" | "trim"
        | "token" | "int" => text_step(op, value, step),
        _ => list_step(op, value, step),
    }
}

/// Applies a step whose input is a list.
fn list_step(op: &str, value: Value, step: &Value) -> Result<Value, String> {
    let items = list(value, op)?;
    match op {
        "where" => {
            let mut out = Vec::new();
            for item in items {
                if matches_where(&item, step)? {
                    out.push(item);
                }
            }
            Ok(Value::Array(out))
        }
        "same" => {
            let (a, b) = (text_arg(step, "a")?, text_arg(step, "b")?);
            let same = |i: &Value| matches!((select(i, a), select(i, b)), (Ok(x), Ok(y)) if json_eq(&x, &y));
            Ok(Value::Array(items.into_iter().filter(same).collect()))
        }
        "pick" => {
            let ptr = text_arg(step, "ptr")?;
            let mut out = Vec::new();
            for item in items {
                match select(&item, ptr)? {
                    Value::Array(inner) if ptr.contains('*') => out.extend(inner),
                    one => out.push(one),
                }
            }
            Ok(Value::Array(out))
        }
        "first" => items
            .into_iter()
            .next()
            .ok_or_else(|| "the list is empty".to_owned()),
        "count" => Ok(Value::from(u64::try_from(items.len()).unwrap_or(u64::MAX))),
        "unique" => {
            let mut out: Vec<Value> = Vec::new();
            for item in items {
                if !out.iter().any(|o| json_eq(o, &item)) {
                    out.push(item);
                }
            }
            Ok(Value::Array(out))
        }
        "sort" => {
            let mut sorted = items;
            sorted.sort_by_key(text_of);
            Ok(Value::Array(sorted))
        }
        "drop" | "take" => {
            let n = step.get("count").and_then(Value::as_u64).unwrap_or(1);
            let n = usize::try_from(n).unwrap_or(usize::MAX);
            let iter = items.into_iter();
            Ok(Value::Array(if op == "drop" {
                iter.skip(n).collect()
            } else {
                iter.take(n).collect()
            }))
        }
        "grep" => {
            let g = text_arg(step, "glob")?;
            let icase = step.get("icase").and_then(Value::as_bool).unwrap_or(false);
            let not = step.get("not").and_then(Value::as_bool).unwrap_or(false);
            let keep = |i: &Value| glob::matches(g, &text_of(i), icase) != not;
            Ok(Value::Array(items.into_iter().filter(keep).collect()))
        }
        other => Err(format!("the step op {other} is not known")),
    }
}

/// Applies a step whose input is a text, or each text of a list.
fn text_step(op: &str, value: Value, step: &Value) -> Result<Value, String> {
    match op {
        "lines" => map_text(value, &|s| {
            let lines = s.lines().map(str::trim).filter(|l| !l.is_empty());
            Ok(Value::Array(lines.map(Value::from).collect()))
        }),
        "split" => {
            let on = text_arg(step, "on")?.to_owned();
            map_text(value, &|s| {
                Ok(Value::Array(
                    s.split(on.as_str()).map(Value::from).collect(),
                ))
            })
        }
        "after" | "before" => {
            let marker = text_arg(step, "text")?.to_owned();
            let after = op == "after";
            map_text(value, &|s| {
                let (head, tail) = s
                    .split_once(marker.as_str())
                    .ok_or_else(|| format!("the text has no {marker:?}"))?;
                Ok(Value::from(if after { tail } else { head }))
            })
        }
        "trim_prefix" | "trim_suffix" => {
            let affix = text_arg(step, "text")?.to_owned();
            let prefix = op == "trim_prefix";
            map_text(value, &|s| {
                let out = if prefix {
                    s.strip_prefix(affix.as_str())
                } else {
                    s.strip_suffix(affix.as_str())
                };
                Ok(Value::from(out.unwrap_or(s)))
            })
        }
        "trim" => map_text(value, &|s| Ok(Value::from(s.trim()))),
        "token" => map_text(value, &|s| Ok(token(s))),
        _ => map_text(value, &|s| {
            parse_int(s)
                .map(|n| Value::Number(Number::from(n)))
                .ok_or_else(|| format!("{s:?} is not an integer"))
        }),
    }
}

/// Gives the literal operand texts of `steps`, for the answer smuggling rule of the lint.
#[must_use]
pub fn operands(steps: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for step in steps {
        if let Value::Object(members) = step {
            for (key, v) in members.iter() {
                match (key, v) {
                    ("op" | "ptr" | "a" | "b" | "var", _) => {}
                    ("key", key_src) => {
                        if let Some(inner) = key_src.get("steps").and_then(Value::as_array) {
                            out.extend(operands(inner));
                        }
                    }
                    (_, Value::String(s)) => out.push(s.clone()),
                    (_, Value::Number(n)) => out.push(n.as_str().to_owned()),
                    _ => {}
                }
            }
        }
    }
    out
}

/// Checks `actual` against the frozen answer `frozen` with the check `check`.
///
/// | Check | Pass when |
/// |---|---|
/// | `equals` | the values are equal |
/// | `glob` | the text matches the frozen glob |
/// | `contains` | the text or list holds the frozen value |
/// | `claim` | `actual` is a verdict whose claim is the frozen claim and whose verdict is `supported` |
/// | `abstain` | `actual` is a verdict `unknown` with at least one gap in `basis.gaps` |
#[must_use]
pub fn check(check: &str, frozen: &Value, actual: &Value) -> bool {
    match check {
        "equals" => json_eq(frozen, actual),
        "glob" => frozen
            .as_str()
            .is_some_and(|g| glob::matches(g, &text_of(actual), false)),
        "contains" => match actual {
            Value::Array(items) => items.iter().any(|i| json_eq(i, frozen)),
            Value::String(s) => s.contains(&text_of(frozen)),
            _ => false,
        },
        "claim" => {
            actual
                .get("claim")
                .is_some_and(|c| json_eq(&canonical_claim(c), &canonical_claim(frozen)))
                && actual.get("verdict").and_then(Value::as_str) == Some("supported")
        }
        "abstain" => {
            actual.get("verdict").and_then(Value::as_str) == frozen.as_str()
                && actual
                    .pointer("/basis/gaps")
                    .and_then(Value::as_array)
                    .is_some_and(|g| !g.is_empty())
        }
        _ => false,
    }
}

/// Gives a claim with its members in the order `rel`, `args`.
fn canonical_claim(c: &Value) -> Value {
    Value::object([
        ("rel", c.get("rel").cloned().unwrap_or(Value::Null)),
        ("args", c.get("args").cloned().unwrap_or(Value::Null)),
    ])
}

#[cfg(test)]
mod tests;
