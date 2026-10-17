//! The `calc` expression engine (design Section 10.4, AC-158).
//!
//! ```text
//! expr   := or
//! or     := xor ( "|" xor )*
//! xor    := and ( "^" and )*
//! and    := shift ( "&" shift )*
//! shift  := sum ( ( "<<" | ">>" ) sum )*
//! sum    := prod ( ( "+" | "-" ) prod )*
//! prod   := unary ( ( "*" | "/" | "%" ) unary )*
//! unary  := ( "-" | "~" | "+" ) unary | atom
//! atom   := "(" expr ")" | term
//! ```
//!
//! A term is a run of characters that are not white space, parentheses or operator marks.
//! A `0x` term is a hex number. A term of digits only gives `ADDRESS_BASE_AMBIGUOUS`, because
//! the server never guesses the base (ADR-0007). Each other term goes to the resolver of the
//! caller: a symbol, a section, a default name, `name@0x..` or an ID.
//!
//! Arithmetic uses 64 bits and wraps. Division and remainder are unsigned. A shift by 64 or
//! more gives 0. The evaluation uses an operator stack, not recursion. Open parentheses and
//! unary operators count as nesting. A nesting depth above [`MAX_DEPTH`] gives
//! `INVALID_ARGUMENT`.

use ghidorah_base::{ErrorCode, hex};
use ghidorah_json::{Object, Value};

use crate::errors::{Candidate, ToolError};

/// The deepest nesting of parentheses and unary operators.
pub const MAX_DEPTH: usize = 64;

/// The longest expression in characters.
pub const MAX_EXPR_CHARS: usize = 1_024;

/// The view names of a value, in output order.
pub const VIEWS: [&str; 8] = ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"];

/// The resolver of the terms that are not numbers. It gives the value of the term.
pub type TermFn<'a> = &'a mut dyn FnMut(&str) -> Result<u64, ToolError>;

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bin {
    Mul,
    Div,
    Rem,
    Add,
    Sub,
    Shl,
    Shr,
    And,
    Xor,
    Or,
}

impl Bin {
    /// Gives the precedence: a higher value binds tighter.
    const fn prec(self) -> u8 {
        match self {
            Self::Mul | Self::Div | Self::Rem => 5,
            Self::Add | Self::Sub => 4,
            Self::Shl | Self::Shr => 3,
            Self::And => 2,
            Self::Xor => 1,
            Self::Or => 0,
        }
    }
}

/// A unary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unary {
    Neg,
    Not,
    Plus,
}

/// One token. A term keeps its byte index in the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok<'a> {
    Term(usize, &'a str),
    Open,
    Close,
    Op(char, Option<Bin>),
}

/// One entry of the operator stack. Each entry keeps the character index of its token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    Open(usize),
    Unary(Unary),
    Bin(Bin, usize),
}

/// Tells if `c` ends a term.
const fn is_mark(c: char) -> bool {
    matches!(
        c,
        '+' | '-' | '*' | '/' | '%' | '<' | '>' | '&' | '|' | '^' | '~' | '(' | ')'
    ) || c.is_ascii_whitespace()
}

/// Gives `INVALID_ARGUMENT` for the expression at the character index `at`.
fn syntax(at: usize, expected: &str) -> ToolError {
    ToolError::new(ErrorCode::InvalidArgument)
        .var("field", "expr")
        .path("/expr")
        .detail("expected", Value::from(expected))
        .detail("at", Value::from(at))
}

/// Splits `text` into tokens with their character indexes.
fn lex(text: &str) -> Result<Vec<(usize, Tok<'_>)>, ToolError> {
    let mut out = Vec::new();
    let mut chars = text.char_indices().enumerate().peekable();
    while let Some((at, (byte, c))) = chars.next() {
        let two = |next: Option<&(usize, (usize, char))>| next.map(|(_, (_, n))| *n) == Some(c);
        let tok = match c {
            c if c.is_ascii_whitespace() => continue,
            '(' => Tok::Open,
            ')' => Tok::Close,
            '*' => Tok::Op(c, Some(Bin::Mul)),
            '/' => Tok::Op(c, Some(Bin::Div)),
            '%' => Tok::Op(c, Some(Bin::Rem)),
            '+' => Tok::Op(c, Some(Bin::Add)),
            '-' => Tok::Op(c, Some(Bin::Sub)),
            '&' => Tok::Op(c, Some(Bin::And)),
            '|' => Tok::Op(c, Some(Bin::Or)),
            '^' => Tok::Op(c, Some(Bin::Xor)),
            '~' => Tok::Op(c, None),
            '<' | '>' if two(chars.peek()) => {
                let _ = chars.next();
                Tok::Op(c, Some(if c == '<' { Bin::Shl } else { Bin::Shr }))
            }
            '<' | '>' => return Err(syntax(at, "the operator << or >>")),
            _ => {
                let mut end = text.len();
                while let Some((_, (next_byte, next))) = chars.peek() {
                    if is_mark(*next) {
                        end = *next_byte;
                        break;
                    }
                    let _ = chars.next();
                }
                Tok::Term(byte, text.get(byte..end).unwrap_or_default())
            }
        };
        out.push((at, tok));
    }
    Ok(out)
}

/// Gives `ADDRESS_BASE_AMBIGUOUS` for the digits term `digits` at `byte` in `text`.
///
/// Each candidate is the whole expression with the term in `0x` hex, in one reading.
fn ambiguous(text: &str, byte: usize, digits: &str) -> ToolError {
    let decimal = digits.parse::<u64>().ok();
    let hexed = hex::parse_digits(digits);
    let head = text.get(..byte).unwrap_or_default();
    let tail = text
        .get(byte.saturating_add(digits.len())..)
        .unwrap_or_default();
    let candidates = [(decimal, "decimal reading"), (hexed, "hex reading")]
        .into_iter()
        .filter_map(|(v, label)| v.map(|v| Candidate::text(&format!("{head}{v:#x}{tail}"), label)))
        .collect();
    ToolError::new(ErrorCode::AddressBaseAmbiguous)
        .path("/expr")
        .candidates(candidates)
}

/// Gives the value of the term `word` at the byte index `byte` of `text`.
fn term_value(
    text: &str,
    byte: usize,
    word: &str,
    term: &mut TermFn<'_>,
) -> Result<u64, ToolError> {
    if word.starts_with("0x") {
        return hex::parse_u64(word).ok_or_else(|| {
            ToolError::new(ErrorCode::AddressInvalid)
                .var("field", "expr")
                .path("/expr")
        });
    }
    if word.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ambiguous(text, byte, word));
    }
    term(word)
}

/// The state of one evaluation: the value stack, the operator stack and the nesting depth.
struct Machine {
    values: Vec<u64>,
    ops: Vec<Entry>,
    depth: usize,
}

impl Machine {
    /// Pushes an entry that counts as nesting.
    fn nest(&mut self, entry: Entry, at: usize) -> Result<(), ToolError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(syntax(
                at,
                "an expression with at most 64 levels of nesting",
            ));
        }
        self.ops.push(entry);
        Ok(())
    }

    /// Applies the top entry of the operator stack.
    fn apply(&mut self, entry: Entry) -> Result<(), ToolError> {
        match entry {
            Entry::Open(at) => Err(syntax(at, "a ) for each (")),
            Entry::Unary(op) => {
                self.depth = self.depth.saturating_sub(1);
                let v = self.values.pop().ok_or_else(|| syntax(0, "an operand"))?;
                self.values.push(match op {
                    Unary::Neg => v.wrapping_neg(),
                    Unary::Not => !v,
                    Unary::Plus => v,
                });
                Ok(())
            }
            Entry::Bin(op, at) => {
                let b = self.values.pop().ok_or_else(|| syntax(at, "an operand"))?;
                let a = self.values.pop().ok_or_else(|| syntax(at, "an operand"))?;
                let zero = || syntax(at, "a divisor other than 0");
                self.values.push(match op {
                    Bin::Mul => a.wrapping_mul(b),
                    Bin::Div => a.checked_div(b).ok_or_else(zero)?,
                    Bin::Rem => a.checked_rem(b).ok_or_else(zero)?,
                    Bin::Add => a.wrapping_add(b),
                    Bin::Sub => a.wrapping_sub(b),
                    Bin::Shl => u32::try_from(b)
                        .ok()
                        .and_then(|s| a.checked_shl(s))
                        .unwrap_or(0),
                    Bin::Shr => u32::try_from(b)
                        .ok()
                        .and_then(|s| a.checked_shr(s))
                        .unwrap_or(0),
                    Bin::And => a & b,
                    Bin::Xor => a ^ b,
                    Bin::Or => a | b,
                });
                Ok(())
            }
        }
    }

    /// Applies the entries above the operator `op`: unary entries and binary entries with a
    /// precedence of at least the precedence of `op`.
    fn reduce(&mut self, op: Bin) -> Result<(), ToolError> {
        while let Some(top) = self.ops.last().copied() {
            let higher = match top {
                Entry::Unary(_) => true,
                Entry::Bin(other, _) => other.prec() >= op.prec(),
                Entry::Open(_) => false,
            };
            if !higher {
                break;
            }
            let _ = self.ops.pop();
            self.apply(top)?;
        }
        Ok(())
    }

    /// Applies the entries down to the open parenthesis of a `)` at `at`.
    fn close(&mut self, at: usize) -> Result<(), ToolError> {
        loop {
            match self.ops.pop() {
                Some(Entry::Open(_)) => {
                    self.depth = self.depth.saturating_sub(1);
                    return Ok(());
                }
                Some(entry) => self.apply(entry)?,
                None => return Err(syntax(at, "a ( before this )")),
            }
        }
    }
}

/// Evaluates the expression `text`. `term` gives the value of each name or ID term.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for a syntax error, a nesting depth above [`MAX_DEPTH`] or a
/// division by zero, `ADDRESS_INVALID` for a bad `0x` term, `ADDRESS_BASE_AMBIGUOUS` for a
/// term of digits only, and the error of `term` for a name that does not resolve.
pub fn eval(text: &str, mut term: TermFn<'_>) -> Result<u64, ToolError> {
    if text.chars().count() > MAX_EXPR_CHARS {
        return Err(syntax(
            MAX_EXPR_CHARS,
            "an expression of at most 1024 characters",
        ));
    }
    let tokens = lex(text)?;
    let mut m = Machine {
        values: Vec::new(),
        ops: Vec::new(),
        depth: 0,
    };
    let mut operand = true;
    for (at, tok) in tokens {
        match (operand, tok) {
            (true, Tok::Term(byte, word)) => {
                m.values.push(term_value(text, byte, word, &mut term)?);
                operand = false;
            }
            (true, Tok::Open) => m.nest(Entry::Open(at), at)?,
            (true, Tok::Op('-', _)) => m.nest(Entry::Unary(Unary::Neg), at)?,
            (true, Tok::Op('~', _)) => m.nest(Entry::Unary(Unary::Not), at)?,
            (true, Tok::Op('+', _)) => m.nest(Entry::Unary(Unary::Plus), at)?,
            (true, _) => return Err(syntax(at, "a number, a name or a (")),
            (false, Tok::Op(_, Some(op))) => {
                m.reduce(op)?;
                m.ops.push(Entry::Bin(op, at));
                operand = true;
            }
            (false, Tok::Close) => m.close(at)?,
            (false, _) => return Err(syntax(at, "an operator or a )")),
        }
    }
    if operand {
        return Err(syntax(
            text.chars().count(),
            "a number or a name at the end",
        ));
    }
    while let Some(entry) = m.ops.pop() {
        m.apply(entry)?;
    }
    match m.values.as_slice() {
        [value] => Ok(*value),
        _ => Err(syntax(0, "one expression")),
    }
}

/// Gives the decimal text of `value` read as a signed 64-bit integer.
#[must_use]
pub fn signed_text(value: u64) -> String {
    i64::from_le_bytes(value.to_le_bytes()).to_string()
}

/// Gives the views of `value`: the decimal text of the value cut to each width of [`VIEWS`],
/// read as unsigned or signed.
#[must_use]
pub fn views(value: u64) -> Value {
    let [b0, b1, b2, b3, ..] = value.to_le_bytes();
    let texts = [
        u8::from_le_bytes([b0]).to_string(),
        u16::from_le_bytes([b0, b1]).to_string(),
        u32::from_le_bytes([b0, b1, b2, b3]).to_string(),
        value.to_string(),
        i8::from_le_bytes([b0]).to_string(),
        i16::from_le_bytes([b0, b1]).to_string(),
        i32::from_le_bytes([b0, b1, b2, b3]).to_string(),
        signed_text(value),
    ];
    let mut out = Object::new();
    for (name, text) in VIEWS.iter().zip(texts) {
        out.push(*name, Value::from(text));
    }
    Value::Object(out)
}
