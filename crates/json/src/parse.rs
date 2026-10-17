//! The strict RFC 8259 parser.
//!
//! The parser keeps the open arrays and objects on a heap stack, not on the call stack.
//! So 100,000 nested arrays give [`Code::Depth`] in a 256 KiB thread (AC-040c).

use crate::error::{Code, JsonError};
use crate::number::{self, Number};
use crate::value::{Object, Value};

/// The default nesting limit of [`Limits`] (design Section 13.6).
pub const DEFAULT_MAX_DEPTH: usize = 128;

/// The default byte limit of [`Limits`]: 16 MiB, the frame cap of the MCP reader.
pub const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;

/// The highest nesting depth that [`parse`] accepts, whatever the limit.
///
/// The drop, clone and compare code of [`Value`] uses one stack frame per level.
/// This ceiling keeps that code inside a small thread stack.
pub const DEPTH_CEILING: usize = 1024;

/// The resource limits of one parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The highest nesting depth of arrays and objects. A top scalar has depth 0.
    ///
    /// The parser uses the smaller of this value and [`DEPTH_CEILING`].
    pub max_depth: usize,
    /// The highest input length in bytes.
    pub max_bytes: usize,
}

impl Limits {
    /// The default limits: depth 128 and 16 MiB.
    pub const DEFAULT: Self = Self {
        max_depth: DEFAULT_MAX_DEPTH,
        max_bytes: DEFAULT_MAX_BYTES,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Parses `text` as one JSON value under `limits`.
///
/// The parser follows RFC 8259 strictly. It accepts only the four white space bytes.
/// It rejects a byte order mark, a lone surrogate escape and data after the value.
/// It keeps number lexemes, member order and repeated member names.
///
/// # Errors
///
/// Returns a [`JsonError`] with the [`Code`] and the byte offset of the first error.
/// [`Code::Depth`] gives the offset of the bracket or brace that is one level too deep.
/// [`Code::Size`] gives the offset `limits.max_bytes`.
pub fn parse(text: &str, limits: &Limits) -> Result<Value, JsonError> {
    if text.len() > limits.max_bytes {
        return Err(JsonError::new(Code::Size, limits.max_bytes));
    }
    let parser = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        max_depth: limits.max_depth.min(DEPTH_CEILING),
    };
    parser.run()
}

/// Parses UTF-8 `bytes` as one JSON value under `limits`.
///
/// # Errors
///
/// Returns [`Code::Size`] when the input is longer than `limits.max_bytes`.
/// Returns [`Code::Utf8`] at the first byte that is not valid UTF-8.
/// Else returns the errors of [`parse`].
pub fn parse_bytes(bytes: &[u8], limits: &Limits) -> Result<Value, JsonError> {
    if bytes.len() > limits.max_bytes {
        return Err(JsonError::new(Code::Size, limits.max_bytes));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|e| JsonError::new(Code::Utf8, e.valid_up_to()))?;
    parse(text, limits)
}

/// An open array or object.
enum Frame {
    /// An array with the items so far.
    Array(Vec<Value>),
    /// An object with the members so far and the name of the next member.
    Object(Object, String),
}

impl Frame {
    /// Gives the byte that closes the frame.
    const fn close(&self) -> u8 {
        match self {
            Self::Array(_) => b']',
            Self::Object(..) => b'}',
        }
    }

    /// Gives the complete value of a closed frame.
    fn into_value(self) -> Value {
        match self {
            Self::Array(items) => Value::Array(items),
            Self::Object(object, _) => Value::Object(object),
        }
    }
}

/// The parser state: the input and the current byte offset.
struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    max_depth: usize,
}

impl Parser<'_> {
    fn err(&self, code: Code) -> JsonError {
        JsonError::new(code, self.pos)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    /// Parses the whole input. Each pass of the outer loop reads one value start.
    fn run(mut self) -> Result<Value, JsonError> {
        let mut stack: Vec<Frame> = Vec::new();
        self.skip_ws();
        loop {
            let Some(mut value) = self.start_value(&mut stack)? else {
                continue;
            };
            // Put the complete value into the open frames. Close each frame that ends here.
            loop {
                let Some(mut frame) = stack.pop() else {
                    self.skip_ws();
                    if self.pos < self.bytes.len() {
                        return Err(self.err(Code::Trailing));
                    }
                    return Ok(value);
                };
                match &mut frame {
                    Frame::Array(items) => items.push(value),
                    Frame::Object(object, key) => object.push(std::mem::take(key), value),
                }
                self.skip_ws();
                match self.peek() {
                    Some(b',') => {
                        self.bump();
                        self.skip_ws();
                        if let Frame::Object(_, key) = &mut frame {
                            *key = self.member_name()?;
                        }
                        stack.push(frame);
                        break;
                    }
                    Some(b) if b == frame.close() => {
                        self.bump();
                        value = frame.into_value();
                    }
                    Some(_) => return Err(self.err(Code::Syntax)),
                    None => return Err(self.err(Code::Eof)),
                }
            }
        }
    }

    /// Reads one value, or opens a frame and gives `None`. White space before it is gone.
    fn start_value(&mut self, stack: &mut Vec<Frame>) -> Result<Option<Value>, JsonError> {
        match self.peek() {
            None => Err(self.err(Code::Eof)),
            Some(b'[') => {
                self.open(stack.len())?;
                if self.peek() == Some(b']') {
                    self.bump();
                    return Ok(Some(Value::Array(Vec::new())));
                }
                stack.push(Frame::Array(Vec::new()));
                Ok(None)
            }
            Some(b'{') => {
                self.open(stack.len())?;
                if self.peek() == Some(b'}') {
                    self.bump();
                    return Ok(Some(Value::Object(Object::new())));
                }
                let key = self.member_name()?;
                stack.push(Frame::Object(Object::new(), key));
                Ok(None)
            }
            Some(b'"') => self.string().map(|s| Some(Value::String(s))),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => {
                let start = self.pos;
                self.pos = number::scan(self.bytes, start)?;
                let lexeme = self
                    .text
                    .get(start..self.pos)
                    .ok_or_else(|| JsonError::new(Code::Number, start))?;
                Ok(Some(Value::Number(Number::from_scanned(lexeme))))
            }
            Some(_) => Err(self.err(Code::Syntax)),
        }
    }

    /// Checks the depth of a new frame inside `open` frames and steps over its bracket.
    fn open(&mut self, open: usize) -> Result<(), JsonError> {
        if open >= self.max_depth {
            return Err(self.err(Code::Depth));
        }
        self.bump();
        self.skip_ws();
        Ok(())
    }

    /// Reads a member name, the `:` after it and the white space around the `:`.
    fn member_name(&mut self) -> Result<String, JsonError> {
        match self.peek() {
            Some(b'"') => {}
            Some(_) => return Err(self.err(Code::Syntax)),
            None => return Err(self.err(Code::Eof)),
        }
        let key = self.string()?;
        self.skip_ws();
        match self.peek() {
            Some(b':') => self.bump(),
            Some(_) => return Err(self.err(Code::Syntax)),
            None => return Err(self.err(Code::Eof)),
        }
        self.skip_ws();
        Ok(key)
    }

    /// Reads the literal `word` and gives `value`.
    fn literal(&mut self, word: &[u8], value: Value) -> Result<Option<Value>, JsonError> {
        for (i, expected) in word.iter().enumerate() {
            let at = self.pos.saturating_add(i);
            match self.bytes.get(at) {
                Some(b) if b == expected => {}
                Some(_) => return Err(JsonError::new(Code::Syntax, at)),
                None => return Err(JsonError::new(Code::Eof, at)),
            }
        }
        self.pos = self.pos.saturating_add(word.len());
        Ok(Some(value))
    }

    /// Adds the input text from `start` to the current offset to `out`.
    fn flush(&self, out: &mut String, start: usize) -> Result<(), JsonError> {
        // Both ends are next to an ASCII byte, so they are on character boundaries.
        let part = self
            .text
            .get(start..self.pos)
            .ok_or_else(|| JsonError::new(Code::Syntax, start))?;
        out.push_str(part);
        Ok(())
    }

    /// Reads a string. The current byte is the opening quote.
    fn string(&mut self) -> Result<String, JsonError> {
        self.bump();
        let mut out = String::new();
        let mut start = self.pos;
        loop {
            match self.peek() {
                None => return Err(self.err(Code::Eof)),
                Some(b'"') => {
                    self.flush(&mut out, start)?;
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.flush(&mut out, start)?;
                    self.escape(&mut out)?;
                    start = self.pos;
                }
                Some(0..=0x1f) => return Err(self.err(Code::Control)),
                Some(_) => self.bump(),
            }
        }
    }

    /// Reads one escape sequence. The current byte is the backslash.
    fn escape(&mut self, out: &mut String) -> Result<(), JsonError> {
        let start = self.pos;
        let next = start.saturating_add(1);
        let c = match self.bytes.get(next) {
            None => return Err(JsonError::new(Code::Eof, next)),
            Some(b'u') => return self.unicode(out),
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(_) => return Err(JsonError::new(Code::Escape, start)),
        };
        out.push(c);
        self.pos = start.saturating_add(2);
        Ok(())
    }

    /// Reads the four hex digits of the `\u` escape at `at`.
    fn hex4(&self, at: usize) -> Result<u16, JsonError> {
        let mut unit: u16 = 0;
        for i in 2..6 {
            let p = at.saturating_add(i);
            let digit = match self.bytes.get(p) {
                None => return Err(JsonError::new(Code::Eof, p)),
                Some(b) => char::from(*b)
                    .to_digit(16)
                    .and_then(|d| u16::try_from(d).ok())
                    .ok_or_else(|| JsonError::new(Code::Escape, at))?,
            };
            unit = unit.wrapping_shl(4) | digit;
        }
        Ok(unit)
    }

    /// Reads a `\u` escape, and the second half of a surrogate pair.
    fn unicode(&mut self, out: &mut String) -> Result<(), JsonError> {
        let start = self.pos;
        let high = self.hex4(start)?;
        self.pos = start.saturating_add(6);
        if !(0xd800..=0xdfff).contains(&high) {
            let c = char::from_u32(u32::from(high))
                .ok_or_else(|| JsonError::new(Code::Surrogate, start))?;
            out.push(c);
            return Ok(());
        }
        if high >= 0xdc00 {
            return Err(JsonError::new(Code::Surrogate, start));
        }
        let second = self.pos;
        match (self.peek(), self.bytes.get(second.saturating_add(1))) {
            (Some(b'\\'), Some(b'u')) => {}
            (None, _) | (Some(b'\\'), None) => {
                return Err(JsonError::new(Code::Eof, self.bytes.len()));
            }
            _ => return Err(JsonError::new(Code::Surrogate, start)),
        }
        let low = self.hex4(second)?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return Err(JsonError::new(Code::Surrogate, start));
        }
        let c = char::decode_utf16([high, low])
            .next()
            .and_then(Result::ok)
            .ok_or_else(|| JsonError::new(Code::Surrogate, start))?;
        out.push(c);
        self.pos = second.saturating_add(6);
        Ok(())
    }
}
