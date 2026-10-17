//! Integer constant expressions in `i128` with checked operations.
//!
//! The grammar is the C grammar of a conditional expression without casts.
//! It has literals, the enum constants of the same text and parentheses.
//! It has the unary operators `- + ~ !`, the binary operators from `*` to `||` and `?:`.
//! An error gives `E_CONST_EXPR`, or `E_OVERFLOW` when a value leaves the `i128` range.

use ghidorah_base::DiagCode;

use super::diag::Fail;
use super::lex::{Tok, Token};
use super::parser::{PResult, Parser, candidates};
use super::words::SIZE_WORDS;

/// The binary operators and their precedence. A higher number binds tighter.
const BINARY: [(&str, u8); 18] = [
    ("||", 1),
    ("&&", 2),
    ("|", 3),
    ("^", 4),
    ("&", 5),
    ("==", 6),
    ("!=", 6),
    ("<", 7),
    (">", 7),
    ("<=", 7),
    (">=", 7),
    ("<<", 8),
    (">>", 8),
    ("+", 9),
    ("-", 9),
    ("*", 10),
    ("/", 10),
    ("%", 10),
];

/// The largest shift count.
const SHIFT_LIMIT: i128 = 128;

fn overflow(t: Token) -> Fail {
    Fail::new(DiagCode::Overflow, t.byte, t.len)
        .hint("The value leaves the 128-bit integer range. Use a smaller value.")
}

fn const_fail(t: Token, hint: &str) -> Fail {
    Fail::new(DiagCode::ConstExpr, t.byte, t.len)
        .expected(&["an integer constant"])
        .hint(hint)
}

/// Applies a binary operator.
fn binary(op: &str, lhs: i128, rhs: i128, tok: Token) -> PResult<i128> {
    let truth = |v: bool| Ok(i128::from(v));
    let over = || overflow(tok);
    match op {
        "||" => truth(lhs != 0 || rhs != 0),
        "&&" => truth(lhs != 0 && rhs != 0),
        "|" => Ok(lhs | rhs),
        "^" => Ok(lhs ^ rhs),
        "&" => Ok(lhs & rhs),
        "==" => truth(lhs == rhs),
        "!=" => truth(lhs != rhs),
        "<" => truth(lhs < rhs),
        ">" => truth(lhs > rhs),
        "<=" => truth(lhs <= rhs),
        ">=" => truth(lhs >= rhs),
        "<<" | ">>" => {
            if !(0..SHIFT_LIMIT).contains(&rhs) {
                return Err(const_fail(tok, "A shift count is from 0 to 127."));
            }
            let count = u32::try_from(rhs).map_err(|_| over())?;
            if op == ">>" {
                return lhs.checked_shr(count).ok_or_else(over);
            }
            let shifted = lhs.checked_shl(count).ok_or_else(over)?;
            if shifted.checked_shr(count) == Some(lhs) {
                Ok(shifted)
            } else {
                Err(over())
            }
        }
        "+" => lhs.checked_add(rhs).ok_or_else(over),
        "-" => lhs.checked_sub(rhs).ok_or_else(over),
        "*" => lhs.checked_mul(rhs).ok_or_else(over),
        "/" | "%" => {
            if rhs == 0 {
                return Err(const_fail(
                    tok,
                    "The divisor is 0. Use a divisor that is not 0.",
                ));
            }
            let value = if op == "/" {
                lhs.checked_div(rhs)
            } else {
                lhs.checked_rem(rhs)
            };
            value.ok_or_else(over)
        }
        _ => Err(const_fail(tok, "The operator is not a C operator.")),
    }
}

impl Parser<'_, '_> {
    /// Parses and evaluates a constant expression.
    pub(crate) fn const_expr(&mut self) -> PResult<i128> {
        let c = self.binary_expr(1)?;
        if self.eat_punct("?").is_none() {
            return Ok(c);
        }
        self.enter()?;
        let a = self.const_expr()?;
        self.expect_punct(":", "`:`")?;
        let b = self.const_expr()?;
        self.leave();
        Ok(if c == 0 { b } else { a })
    }

    /// Gives the current binary operator and its precedence.
    fn peek_binary(&self) -> Option<(&'static str, u8, Token)> {
        let t = self.peek()?;
        let Tok::Punct(p) = t.tok else {
            return None;
        };
        BINARY
            .iter()
            .find(|(op, _)| *op == p)
            .map(|(op, prec)| (*op, *prec, t))
    }

    /// Parses binary operators with a precedence of `min` or more.
    fn binary_expr(&mut self, min: u8) -> PResult<i128> {
        let mut lhs = self.unary()?;
        while let Some((op, prec, t)) = self.peek_binary() {
            if prec < min {
                break;
            }
            self.bump();
            let rhs = self.binary_expr(prec.saturating_add(1))?;
            lhs = binary(op, lhs, rhs, t)?;
        }
        Ok(lhs)
    }

    /// Parses a unary expression.
    fn unary(&mut self) -> PResult<i128> {
        let Some(t) = self.peek() else {
            return Err(self.unexpected(&["an integer constant"]));
        };
        let Tok::Punct(op @ ("-" | "+" | "~" | "!")) = t.tok else {
            return self.primary();
        };
        self.enter()?;
        self.bump();
        let v = self.unary()?;
        self.leave();
        match op {
            "-" => v.checked_neg().ok_or_else(|| overflow(t)),
            "~" => Ok(!v),
            "!" => Ok(i128::from(v == 0)),
            _ => Ok(v),
        }
    }

    /// Parses a literal, an enum constant or a parenthesized expression.
    fn primary(&mut self) -> PResult<i128> {
        let Some(t) = self.peek() else {
            return Err(self.unexpected(&["an integer constant"]));
        };
        match t.tok {
            Tok::Int(Some(v)) => {
                self.bump();
                i128::try_from(v).map_err(|_| overflow(t))
            }
            Tok::Int(None) => Err(overflow(t)),
            Tok::Punct("(") => {
                self.enter()?;
                self.bump();
                let v = self.const_expr()?;
                self.expect_punct(")", "`)`")?;
                self.leave();
                Ok(v)
            }
            Tok::Ident => {
                let word = self.word(t);
                if SIZE_WORDS.contains(&word) {
                    return Err(const_fail(
                        t,
                        "The parser does not evaluate sizeof or alignof. Use an integer constant.",
                    ));
                }
                if let Some(v) = self.consts.get(word).copied() {
                    self.bump();
                    return Ok(v);
                }
                let names: Vec<&str> = self.consts.keys().map(String::as_str).collect();
                Err(
                    const_fail(t, "The name is not an enum constant of the text.")
                        .candidates(candidates(word, &names)),
                )
            }
            _ => Err(self.unexpected(&["an integer constant"])),
        }
    }
}
