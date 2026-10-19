//! A small evaluator of C integer expressions for the `xor` derive step.
//!
//! An agent reads a key function in pseudo-C, for example `return (uint32_t)(i * 3 + 0x5a);`,
//! and computes the key of each byte. This module does the same computation. It knows the
//! operators `| ^ & << >> + - * / % ~` and unary `-`, parentheses, hex and decimal numbers,
//! one variable and casts to the C integer types. Arithmetic wraps at 64 bits. A cast to a
//! narrow type keeps its low bits.

/// The largest nesting depth of an expression.
pub const MAX_DEPTH: usize = 64;

/// The largest expression text in bytes.
pub const MAX_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Num(u64),
    Ident(String),
    Op(&'static str),
    Open,
    Close,
}

/// The operators, longest first so that `<<` wins over `<`.
const OPS: [&str; 12] = ["<<", ">>", "|", "^", "&", "+", "-", "*", "/", "%", "~", "!"];

fn lex(text: &str) -> Result<Vec<Tok>, String> {
    if text.len() > MAX_LEN {
        return Err("the expression is too long".to_owned());
    }
    let mut out = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        let c = rest.chars().next().unwrap_or(' ');
        if c == '(' || c == ')' {
            out.push(if c == '(' { Tok::Open } else { Tok::Close });
            rest = &rest[1..];
        } else if c.is_ascii_digit() {
            let end = rest
                .find(|ch: char| !ch.is_ascii_alphanumeric())
                .unwrap_or(rest.len());
            out.push(Tok::Num(number(&rest[..end])?));
            rest = &rest[end..];
        } else if c.is_ascii_alphabetic() || c == '_' {
            let end = rest
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .unwrap_or(rest.len());
            out.push(Tok::Ident(rest[..end].to_owned()));
            rest = &rest[end..];
        } else if let Some(op) = OPS.iter().find(|op| rest.starts_with(**op)) {
            out.push(Tok::Op(op));
            rest = &rest[op.len()..];
        } else {
            return Err(format!("the character {c:?} is not part of an expression"));
        }
        rest = rest.trim_start();
    }
    Ok(out)
}

/// Parses a C number: hex with `0x` or decimal, with optional `u` and `l` suffixes.
fn number(text: &str) -> Result<u64, String> {
    let body = text.trim_end_matches(['u', 'U', 'l', 'L']);
    let parsed = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .map_or_else(
            || body.parse::<u64>().ok(),
            |hex| u64::from_str_radix(hex, 16).ok(),
        );
    parsed.ok_or_else(|| format!("{text} is not a number"))
}

/// The bit width of a C integer type name, or `None` for a name that is not a type.
fn type_bits(name: &str) -> Option<u32> {
    match name {
        "uint8_t" | "int8_t" | "char" | "uchar" | "bool" => Some(8),
        "uint16_t" | "int16_t" | "short" => Some(16),
        "uint32_t" | "int32_t" | "int" | "unsigned" => Some(32),
        "uint64_t" | "int64_t" | "long" | "size_t" | "uintptr_t" | "intptr_t" => Some(64),
        _ => None,
    }
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    var: &'a str,
    value: u64,
}

/// The binary operators by level, from the lowest binding to the highest.
const LEVELS: [&[&str]; 6] = [
    &["|"],
    &["^"],
    &["&"],
    &["<<", ">>"],
    &["+", "-"],
    &["*", "/", "%"],
];

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn binary(&mut self, level: usize, depth: usize) -> Result<u64, String> {
        let Some(ops) = LEVELS.get(level) else {
            return self.unary(depth);
        };
        let mut left = self.binary(level + 1, depth)?;
        while let Some(Tok::Op(op)) = self.peek() {
            let op = *op;
            if !ops.contains(&op) {
                break;
            }
            self.pos += 1;
            let right = self.binary(level + 1, depth)?;
            left = apply(op, left, right)?;
        }
        Ok(left)
    }

    /// Tells if the tokens at the position are a cast, and gives its width and length.
    fn cast(&self) -> Option<(u32, usize)> {
        let Some(Tok::Open) = self.peek() else {
            return None;
        };
        let mut bits = None;
        let mut i = self.pos + 1;
        while let Some(tok) = self.toks.get(i) {
            match tok {
                Tok::Ident(name) if name == "const" || name == "unsigned" || name == "signed" => {
                    bits = bits.or(Some(32));
                }
                Tok::Ident(name) => bits = Some(type_bits(name)?),
                Tok::Op("*") => bits = bits.map(|_| 64),
                Tok::Close => return bits.map(|b| (b, i + 1 - self.pos)),
                _ => return None,
            }
            i += 1;
        }
        None
    }

    fn unary(&mut self, depth: usize) -> Result<u64, String> {
        if depth > MAX_DEPTH {
            return Err("the expression is too deep".to_owned());
        }
        if let Some((bits, len)) = self.cast() {
            self.pos += len;
            let value = self.unary(depth + 1)?;
            return Ok(if bits >= 64 {
                value
            } else {
                value & ((1u64 << bits) - 1)
            });
        }
        match self.peek().cloned() {
            Some(Tok::Op("~")) => {
                self.pos += 1;
                Ok(!self.unary(depth + 1)?)
            }
            Some(Tok::Op("-")) => {
                self.pos += 1;
                Ok(self.unary(depth + 1)?.wrapping_neg())
            }
            Some(Tok::Op("!")) => {
                self.pos += 1;
                Ok(u64::from(self.unary(depth + 1)? == 0))
            }
            Some(Tok::Num(n)) => {
                self.pos += 1;
                Ok(n)
            }
            Some(Tok::Ident(name)) if name == self.var => {
                self.pos += 1;
                Ok(self.value)
            }
            Some(Tok::Ident(name)) => Err(format!("{name} is not the variable {}", self.var)),
            Some(Tok::Open) => {
                self.pos += 1;
                let value = self.binary(0, depth + 1)?;
                if self.peek() != Some(&Tok::Close) {
                    return Err("a closing parenthesis is missing".to_owned());
                }
                self.pos += 1;
                Ok(value)
            }
            _ => Err("an operand is missing".to_owned()),
        }
    }
}

fn apply(op: &str, a: u64, b: u64) -> Result<u64, String> {
    Ok(match op {
        "|" => a | b,
        "^" => a ^ b,
        "&" => a & b,
        "<<" => a.wrapping_shl(u32::try_from(b & 63).unwrap_or(0)),
        ">>" => a.wrapping_shr(u32::try_from(b & 63).unwrap_or(0)),
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "/" => a.checked_div(b).ok_or("division by zero")?,
        "%" => a.checked_rem(b).ok_or("division by zero")?,
        _ => return Err(format!("{op} is not a binary operator")),
    })
}

/// Evaluates `text` with the variable `var` set to `value`.
///
/// # Errors
///
/// Returns a message when the text is not an expression of this grammar, when it names
/// another variable or when it divides by zero.
pub fn eval(text: &str, var: &str, value: u64) -> Result<u64, String> {
    let toks = lex(text)?;
    let mut parser = Parser {
        toks: &toks,
        pos: 0,
        var,
        value,
    };
    let out = parser.binary(0, 0)?;
    if parser.pos != toks.len() {
        return Err("the expression has extra text at its end".to_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
