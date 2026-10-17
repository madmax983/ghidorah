//! Small strict JSON value, parser and writer for xtask.
//!
//! The xtask crate reads `cargo metadata`, `cargo --message-format=json` and `llvm-cov` output.
//! Objects keep their keys in sorted order, so the writer output is deterministic.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

/// The maximum nesting depth that [`parse`] accepts.
pub const MAX_DEPTH: usize = 128;

/// One JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// The `null` literal.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number in its source text form.
    Number(String),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Self>),
    /// An object with sorted keys.
    Object(BTreeMap<String, Self>),
}

/// A parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The byte offset of the failure.
    pub offset: usize,
    /// What is wrong.
    pub message: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for ParseError {}

/// Parses one JSON text (RFC 8259).
///
/// # Errors
///
/// Returns a [`ParseError`] for bad syntax, a duplicate key, trailing data or nesting above [`MAX_DEPTH`].
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos == parser.bytes.len() {
        Ok(value)
    } else {
        Err(parser.fail("trailing data"))
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    const fn fail(&self, message: &'static str) -> ParseError {
        ParseError {
            offset: self.pos,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect_byte(&mut self, byte: u8, message: &'static str) -> Result<(), ParseError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.fail(message))
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, ParseError> {
        let end = self.pos.saturating_add(word.len());
        if self.bytes.get(self.pos..end) == Some(word.as_bytes()) {
            self.pos = end;
            Ok(value)
        } else {
            Err(self.fail("bad literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.fail("unexpected byte")),
            None => Err(self.fail("unexpected end")),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.fail("nesting too deep"));
        }
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Value::Array(items)),
                _ => return Err(self.fail("expected , or ]")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.fail("nesting too deep"));
        }
        self.pos += 1;
        let mut members = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.fail("expected a key"));
            }
            let key_pos = self.pos;
            let key = self.string()?;
            self.skip_ws();
            self.expect_byte(b':', "expected :")?;
            self.skip_ws();
            let value = self.value(depth)?;
            if members.insert(key, value).is_some() {
                return Err(ParseError {
                    offset: key_pos,
                    message: "duplicate key",
                });
            }
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Value::Object(members)),
                _ => return Err(self.fail("expected , or }")),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let int_start = self.pos;
        let count = self.digits();
        if count == 0 {
            return Err(self.fail("expected a digit"));
        }
        if count > 1 && self.bytes.get(int_start) == Some(&b'0') {
            return Err(self.fail("leading zero"));
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if self.digits() == 0 {
                return Err(self.fail("expected a fraction digit"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err(self.fail("expected an exponent digit"));
            }
        }
        let text = self.bytes.get(start..self.pos).unwrap_or_default();
        Ok(Value::Number(String::from_utf8_lossy(text).into_owned()))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut code = 0u32;
        for _ in 0..4 {
            let digit = self
                .bump()
                .and_then(|b| char::from(b).to_digit(16))
                .ok_or_else(|| self.fail("bad unicode escape"))?;
            code = code * 16 + digit;
        }
        Ok(code)
    }

    fn escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let ch = match self.bump() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let first = self.hex4()?;
                let code = if (0xD800..0xDC00).contains(&first) {
                    if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                        return Err(self.fail("lone surrogate"));
                    }
                    let second = self.hex4()?;
                    if !(0xDC00..0xE000).contains(&second) {
                        return Err(self.fail("lone surrogate"));
                    }
                    0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                } else {
                    first
                };
                char::from_u32(code).ok_or_else(|| self.fail("lone surrogate"))?
            }
            _ => return Err(self.fail("bad escape")),
        };
        out.push(ch);
        Ok(())
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while matches!(self.peek(), Some(b) if b != b'"' && b != b'\\' && b >= 0x20) {
                self.pos += 1;
            }
            let run = self.bytes.get(start..self.pos).unwrap_or_default();
            let text = std::str::from_utf8(run).map_err(|_| self.fail("bad UTF-8"))?;
            out.push_str(text);
            match self.bump() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => self.escape(&mut out)?,
                Some(_) => return Err(self.fail("control character in string")),
                None => return Err(self.fail("unterminated string")),
            }
        }
    }
}

/// Writes a value as compact JSON text.
#[must_use]
pub fn write(value: &Value) -> String {
    let mut out = String::new();
    write_into(&mut out, value);
    out
}

fn write_into(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(text) => out.push_str(text),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_into(out, item);
            }
            out.push(']');
        }
        Value::Object(members) => {
            out.push('{');
            for (i, (key, item)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_into(out, item);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

impl Value {
    /// Makes an object from key and value pairs.
    pub fn object<K: Into<String>>(items: impl IntoIterator<Item = (K, Self)>) -> Self {
        Self::Object(items.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Gives the member `key` of an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_object().and_then(|m| m.get(key))
    }

    /// Resolves an RFC 6901 pointer.
    #[must_use]
    pub fn pointer(&self, pointer: &str) -> Option<&Self> {
        if pointer.is_empty() {
            return Some(self);
        }
        let rest = pointer.strip_prefix('/')?;
        rest.split('/').try_fold(self, |node, raw| {
            let token = raw.replace("~1", "/").replace("~0", "~");
            match node {
                Self::Object(members) => members.get(&token),
                Self::Array(items) => token.parse::<usize>().ok().and_then(|i| items.get(i)),
                _ => None,
            }
        })
    }

    /// Gives the text of a string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    /// Gives the value of a boolean.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    /// Gives a number as `u64` when it is a non-negative integer that fits.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(text) => text.parse().ok(),
            _ => None,
        }
    }

    /// Gives a number as `f64`.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(text) => text.parse().ok(),
            _ => None,
        }
    }

    /// Gives the items of an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Gives the members of an object.
    #[must_use]
    pub const fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(members) => Some(members),
            _ => None,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&write(self))
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::String(text.to_owned())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Self::String(text)
    }
}

impl From<bool> for Value {
    fn from(flag: bool) -> Self {
        Self::Bool(flag)
    }
}

impl From<u64> for Value {
    fn from(number: u64) -> Self {
        Self::Number(number.to_string())
    }
}

impl From<usize> for Value {
    fn from(number: usize) -> Self {
        Self::Number(number.to_string())
    }
}

impl From<Vec<Self>> for Value {
    fn from(items: Vec<Self>) -> Self {
        Self::Array(items)
    }
}
