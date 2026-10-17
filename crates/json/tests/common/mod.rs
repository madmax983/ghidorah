//! Shared helpers of the JSON tests: random values and the suite directory.

#![allow(dead_code, reason = "each test binary uses a part of the helpers")]

use std::path::PathBuf;

use ghidorah_json::{Limits, Number, Object, Value};
use ghidorah_testkit::pbt::Gen;

/// Gives the directory of the vendored `JSONTestSuite` files.
pub fn suite_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/jsontestsuite")
}

/// Gives the default limits.
pub fn limits() -> Limits {
    Limits::default()
}

/// Characters that stress the string writer: escapes, controls, non-BMP and wide forms.
const CHARS: &[char] = &[
    'a',
    'Z',
    '0',
    ' ',
    '"',
    '\\',
    '/',
    '\u{0}',
    '\u{1}',
    '\u{8}',
    '\u{9}',
    '\u{a}',
    '\u{c}',
    '\u{d}',
    '\u{1f}',
    '\u{7f}',
    '\u{80}',
    'é',
    '€',
    '\u{2028}',
    '\u{fb33}',
    '\u{fffd}',
    '\u{ffff}',
    '😀',
    '\u{10ffff}',
    '~',
];

/// Draws a string of up to 12 characters from [`CHARS`] and random scalar values.
pub fn string(g: &mut Gen) -> String {
    g.vec(12, |g| {
        if g.bool() {
            g.pick(CHARS).copied().unwrap_or('a')
        } else {
            let raw = u32::try_from(g.draw(0x11_0000)).unwrap_or(0);
            char::from_u32(raw).unwrap_or('?')
        }
    })
    .into_iter()
    .collect()
}

/// Draws a digit string of 1 to `max` digits. The first digit is not `0` when `lead` is false.
fn digits(g: &mut Gen, max: u64, lead: bool) -> String {
    let len = g.range(1, max);
    let mut out = String::new();
    for i in 0..len {
        let low = u64::from(i == 0 && !lead);
        let d = g.range(low, 9);
        out.push(char::from_digit(u32::try_from(d).unwrap_or(0), 10).unwrap_or('0'));
    }
    out
}

/// Draws a valid number lexeme, or a number from an integer or a finite `f64`.
pub fn number(g: &mut Gen) -> Number {
    match g.draw(4) {
        0 => Number::from(g.u64()),
        1 => Number::from(i64::from_ne_bytes(g.u64().to_ne_bytes())),
        2 => {
            let bits = g.u64();
            Number::from_f64(f64::from_bits(bits)).unwrap_or_else(|| Number::from(0u8))
        }
        _ => {
            let mut text = String::new();
            if g.bool() {
                text.push('-');
            }
            if g.bool() {
                text.push('0');
            } else {
                text.push_str(&digits(g, 30, false));
            }
            if g.bool() {
                text.push('.');
                text.push_str(&digits(g, 20, true));
            }
            if g.bool() {
                text.push(*g.pick(&['e', 'E']).unwrap_or(&'e'));
                if let Some(sign) = g.pick(&["", "+", "-"]) {
                    text.push_str(sign);
                }
                text.push_str(&digits(g, 5, true));
            }
            Number::parse(&text).unwrap_or_else(|e| panic!("lexeme {text:?} must parse: {e}"))
        }
    }
}

/// Draws a random value with at most `depth` levels of arrays and objects.
pub fn value(g: &mut Gen, depth: u32) -> Value {
    let kinds = if depth == 0 { 4 } else { 6 };
    match g.draw(kinds) {
        0 => Value::Null,
        1 => Value::Bool(g.bool()),
        2 => Value::Number(number(g)),
        3 => Value::String(string(g)),
        4 => Value::Array(g.vec(5, |g| value(g, depth - 1))),
        _ => {
            let members = g.vec(5, |g| (string(g), value(g, depth - 1)));
            Value::Object(members.into_iter().collect::<Object>())
        }
    }
}

/// Draws an object with unique member names, so it has a JCS form.
pub fn unique_object(g: &mut Gen, depth: u32) -> Object {
    let mut object = Object::new();
    for (i, (key, value)) in g
        .vec(6, |g| (string(g), jcs_value(g, depth.saturating_sub(1))))
        .into_iter()
        .enumerate()
    {
        object.insert(format!("{key}{i}"), value);
    }
    object
}

/// Draws a random value with unique member names and `f64` numbers, so it has a JCS form.
pub fn jcs_value(g: &mut Gen, depth: u32) -> Value {
    let kinds = if depth == 0 { 4 } else { 6 };
    match g.draw(kinds) {
        0 => Value::Null,
        1 => Value::Bool(g.bool()),
        2 => Value::from_f64(f64::from_bits(g.u64())).unwrap_or_else(|| Value::from(1u8)),
        3 => Value::String(string(g)),
        4 => Value::Array(g.vec(4, |g| jcs_value(g, depth - 1))),
        _ => Value::Object(unique_object(g, depth)),
    }
}
