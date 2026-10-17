//! The writers: compact, pretty and the engine that JCS uses.
//!
//! One engine writes all forms. It keeps the open arrays and objects on a heap stack,
//! so a deep value cannot overflow the call stack.

use std::convert::Infallible;

use crate::number::Number;
use crate::value::{Object, Value};

/// The members of an object in output order, or a form error and the name of the bad member.
pub(crate) type Members<'a, E> = Result<Vec<&'a (String, Value)>, (E, &'a str)>;

/// One output form of the writer engine.
pub(crate) trait Form {
    /// The error of the form. The compact and pretty forms cannot fail.
    type Error;

    /// The indent of one level, or `None` for output with no white space.
    const INDENT: Option<&'static str>;

    /// Writes one number.
    ///
    /// # Errors
    ///
    /// Returns the error of a number that has no text in this form.
    fn number(number: &Number, out: &mut String) -> Result<(), Self::Error>;

    /// Gives the members of an object in output order.
    ///
    /// # Errors
    ///
    /// Returns the error and the name of the bad member.
    fn members(object: &Object) -> Members<'_, Self::Error>;
}

/// The compact form: no white space, members in insertion order.
struct Compact;

/// The pretty form: two spaces of indent per level, members in insertion order.
struct Pretty;

impl Form for Compact {
    type Error = Infallible;
    const INDENT: Option<&'static str> = None;

    fn number(number: &Number, out: &mut String) -> Result<(), Infallible> {
        out.push_str(number.as_str());
        Ok(())
    }

    fn members(object: &Object) -> Members<'_, Infallible> {
        Ok(object.members().iter().collect())
    }
}

impl Form for Pretty {
    type Error = Infallible;
    const INDENT: Option<&'static str> = Some("  ");

    fn number(number: &Number, out: &mut String) -> Result<(), Infallible> {
        Compact::number(number, out)
    }

    fn members(object: &Object) -> Members<'_, Infallible> {
        Compact::members(object)
    }
}

/// Gives the output of a form that cannot fail.
fn infallible(result: Result<String, (Infallible, String)>) -> String {
    match result {
        Ok(text) => text,
        Err((never, _)) => match never {},
    }
}

/// Writes `value` as compact JSON text, with members in insertion order.
///
/// A number keeps its lexeme. A string escapes `"`, `\` and U+0000 to U+001F only.
/// The output never holds `NaN` or `inf`, and [`crate::parse`] reads it back as the same value.
#[must_use]
pub fn write(value: &Value) -> String {
    infallible(render::<Compact>(value))
}

/// Writes `value` as JSON text with two spaces of indent per level and a `": "` separator.
///
/// An empty array gives `[]`, and an empty object gives `{}`. The text has no final newline.
#[must_use]
pub fn write_pretty(value: &Value) -> String {
    infallible(render::<Pretty>(value))
}

/// The items of one open array or object.
enum Items<'a> {
    Array(&'a [Value]),
    Object(Vec<&'a (String, Value)>),
}

/// One open array or object and the index of its next item.
struct Level<'a> {
    items: Items<'a>,
    next: usize,
}

impl<'a> Level<'a> {
    /// Gives the next item with its member name, and steps past it.
    fn take(&mut self) -> Option<(Option<&'a str>, &'a Value)> {
        let item = match &self.items {
            Items::Array(items) => items.get(self.next).map(|v| (None, v)),
            Items::Object(members) => members.get(self.next).map(|(k, v)| (Some(k.as_str()), v)),
        }?;
        self.next = self.next.saturating_add(1);
        Some(item)
    }

    /// Gives the path segment of the item that the level writes now.
    fn segment(&self) -> Option<String> {
        let index = self.next.checked_sub(1)?;
        match &self.items {
            Items::Array(_) => Some(index.to_string()),
            Items::Object(members) => members.get(index).map(|(k, _)| k.clone()),
        }
    }

    const fn close(&self) -> char {
        match self.items {
            Items::Array(_) => ']',
            Items::Object(_) => '}',
        }
    }
}

/// Gives the RFC 6901 pointer of the current item, plus the segment `last` when it is `Some`.
fn path_of(stack: &[Level<'_>], last: Option<&str>) -> String {
    let mut path = String::new();
    for segment in stack.iter().filter_map(Level::segment) {
        push_segment(&mut path, &segment);
    }
    if let Some(last) = last {
        push_segment(&mut path, last);
    }
    path
}

/// Adds `/` and `token` with the RFC 6901 escapes to `path`.
pub(crate) fn push_segment(path: &mut String, token: &str) {
    path.push('/');
    for c in token.chars() {
        match c {
            '~' => path.push_str("~0"),
            '/' => path.push_str("~1"),
            _ => path.push(c),
        }
    }
}

/// Adds a newline and the indent of `depth` levels, in a pretty form.
fn newline<F: Form>(out: &mut String, depth: usize) {
    if let Some(indent) = F::INDENT {
        out.push('\n');
        for _ in 0..depth {
            out.push_str(indent);
        }
    }
}

/// Writes `root` in the form `F`.
///
/// # Errors
///
/// Returns the error of the form and the pointer of the bad part.
pub(crate) fn render<F: Form>(root: &Value) -> Result<String, (F::Error, String)> {
    let mut out = String::new();
    let mut stack: Vec<Level<'_>> = Vec::new();
    let mut next = Some(root);
    loop {
        if let Some(value) = next.take() {
            match value {
                Value::Null => out.push_str("null"),
                Value::Bool(true) => out.push_str("true"),
                Value::Bool(false) => out.push_str("false"),
                Value::Number(n) => {
                    F::number(n, &mut out).map_err(|e| (e, path_of(&stack, None)))?;
                }
                Value::String(s) => write_string(&mut out, s),
                Value::Array(items) if items.is_empty() => out.push_str("[]"),
                Value::Object(object) if object.is_empty() => out.push_str("{}"),
                Value::Array(items) => {
                    out.push('[');
                    stack.push(Level {
                        items: Items::Array(items),
                        next: 0,
                    });
                }
                Value::Object(object) => {
                    let members =
                        F::members(object).map_err(|(e, key)| (e, path_of(&stack, Some(key))))?;
                    out.push('{');
                    stack.push(Level {
                        items: Items::Object(members),
                        next: 0,
                    });
                }
            }
        }
        let depth = stack.len();
        let Some(level) = stack.last_mut() else {
            return Ok(out);
        };
        if let Some((key, value)) = level.take() {
            if level.next > 1 {
                out.push(',');
            }
            newline::<F>(&mut out, depth);
            if let Some(key) = key {
                write_string(&mut out, key);
                out.push(':');
                if F::INDENT.is_some() {
                    out.push(' ');
                }
            }
            next = Some(value);
        } else {
            let close = level.close();
            stack.pop();
            newline::<F>(&mut out, stack.len());
            out.push(close);
        }
    }
}

/// Writes `text` as a JSON string.
///
/// The escapes are `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t` and `\u00xx` (lowercase hex)
/// for the other control characters. This is also the string form of RFC 8785.
pub(crate) fn write_string(out: &mut String, text: &str) {
    out.push('"');
    let mut start = 0;
    for (i, b) in text.bytes().enumerate() {
        let short = match b {
            b'"' => Some("\\\""),
            b'\\' => Some("\\\\"),
            0x08 => Some("\\b"),
            0x0c => Some("\\f"),
            b'\n' => Some("\\n"),
            b'\r' => Some("\\r"),
            b'\t' => Some("\\t"),
            0..=0x1f => None,
            _ => continue,
        };
        // An escaped byte is ASCII, so `i` is on a character boundary.
        out.push_str(text.get(start..i).unwrap_or_default());
        if let Some(short) = short {
            out.push_str(short);
        } else {
            out.push_str("\\u00");
            for nibble in [u32::from(b).wrapping_shr(4), u32::from(b) & 0xf] {
                out.push(char::from_digit(nibble, 16).unwrap_or('0'));
            }
        }
        start = i.saturating_add(1);
    }
    out.push_str(text.get(start..).unwrap_or_default());
    out.push('"');
}
