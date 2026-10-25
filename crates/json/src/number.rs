//! The JSON number: a raw lexeme that matches the RFC 8259 grammar.

use std::fmt;
use std::str::FromStr;

use crate::error::{Code, JsonError};

/// The largest decimal exponent `n` that the ECMAScript form writes without an exponent part.
const ES_MAX_PLAIN: i32 = 21;

/// The smallest decimal exponent `n` that the ECMAScript form writes as `0.000ddd`.
const ES_MIN_PLAIN: i32 = -5;

/// A JSON number that keeps its raw lexeme.
///
/// The lexeme always matches the RFC 8259 grammar
/// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
/// So `9007199254740993` keeps all its digits, and the writer never emits `NaN` or `inf`.
/// Two numbers are equal when their lexemes are equal: `1.0` and `1` are different numbers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Number(String);

impl Number {
    /// Parses `text` as one number lexeme.
    ///
    /// The text must be the whole lexeme, with no white space.
    ///
    /// # Errors
    ///
    /// Returns [`Code::Number`] or [`Code::Eof`] with the offset of the first bad byte.
    /// Returns [`Code::Trailing`] when bytes follow a valid lexeme.
    pub fn parse(text: &str) -> Result<Self, JsonError> {
        let end = scan(text.as_bytes(), 0)?;
        if end == text.len() {
            Ok(Self(text.to_owned()))
        } else {
            Err(JsonError::new(Code::Trailing, end))
        }
    }

    /// Makes a number from a lexeme that [`scan`] accepts.
    pub(crate) fn from_scanned(lexeme: &str) -> Self {
        Self(lexeme.to_owned())
    }

    /// Makes a number from a finite `f64`.
    ///
    /// The lexeme is the shortest text that reads back as the same `f64`.
    /// `NaN` and the infinities give `None`, so no writer can emit them.
    #[must_use]
    pub fn from_f64(value: f64) -> Option<Self> {
        if value.is_finite() {
            // `{:?}` gives the shortest round-trip digits, for example `0.1`, `1e21` or `-0.0`.
            Self::parse(&format!("{value:?}")).ok()
        } else {
            None
        }
    }

    /// Gives the raw lexeme.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Tells if the lexeme has no fraction part and no exponent part.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        !self.0.contains(['.', 'e', 'E'])
    }

    /// Gives the value as `u64` when the lexeme is an integer in range.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        if !self.is_integer() {
            return None;
        }
        match self.0.strip_prefix('-') {
            Some("0") => Some(0),
            Some(_) => None,
            None => self.0.parse().ok(),
        }
    }

    /// Gives the value as `i64` when the lexeme is an integer in range.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        if self.is_integer() {
            self.0.parse().ok()
        } else {
            None
        }
    }

    /// Gives the nearest `f64`, or `None` when the value is outside the `f64` range.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        // The grammar check comes first, so the std parser sees only RFC 8259 lexemes.
        self.0.parse::<f64>().ok().filter(|x| x.is_finite())
    }

    /// Gives the lexeme when it is already the JCS text: a short integer, which is exact as `f64`.
    ///
    /// The lexeme has at most 15 digits, so it is below 2^53. Its grammar allows no leading zero.
    /// The text `-0` is not plain, because JCS writes it as `0`.
    #[must_use]
    pub fn jcs_plain(&self) -> Option<&str> {
        let digits = self.0.strip_prefix('-').unwrap_or(&self.0);
        let plain =
            digits.len() <= 15 && digits.bytes().all(|b| b.is_ascii_digit()) && self.0 != "-0";
        plain.then_some(self.0.as_str())
    }

    /// Gives the RFC 8785 (JCS) text of the number, or `None` when it is outside the `f64` range.
    ///
    /// JCS writes the nearest `f64` in the ECMAScript form, for example `1e+21` and `0.000001`.
    /// So an integer above 2^53 can lose its low digits in this form.
    #[must_use]
    pub fn to_jcs(&self) -> Option<String> {
        if let Some(plain) = self.jcs_plain() {
            return Some(plain.to_owned());
        }
        let x = self.as_f64()?;
        if x.abs().to_bits() == 0 {
            return Some("0".to_owned());
        }
        let (digits, exp) = shortest(x.abs())?;
        let mut out = String::new();
        if x.is_sign_negative() {
            out.push('-');
        }
        es_body(&digits, exp.checked_add(1)?, &mut out)?;
        Some(out)
    }
}

/// The precision that gives every significant digit of an `f64` (at most 767 digits).
const EXACT_PRECISION: usize = 780;

/// Splits the `{:e}` text `d.ddde<exp>` into its digits and its exponent.
fn sci_parts(text: &str) -> Option<(String, i32)> {
    let (mantissa, exp) = text.split_once('e')?;
    let digits = mantissa.chars().filter(char::is_ascii_digit).collect();
    Some((digits, exp.parse().ok()?))
}

/// Gives the text `d.ddde<exp>` of `digits` and `exp`.
fn sci_text(digits: &str, exp: i32) -> Option<String> {
    let (first, rest) = (digits.get(..1)?, digits.get(1..)?);
    if rest.is_empty() {
        Some(format!("{first}e{exp}"))
    } else {
        Some(format!("{first}.{rest}e{exp}"))
    }
}

/// Gives the shortest round-trip digits of a positive finite `x` and the exponent of the first digit.
///
/// `{:e}` gives the shortest digits. It also gives the nearest candidate, but a tie between two
/// candidates can go to the odd one. ECMA-262 takes the even one, so this function checks for a tie.
fn shortest(x: f64) -> Option<(String, i32)> {
    let (digits, exp) = sci_parts(&format!("{x:e}"))?;
    let k = digits.len();
    // A tie needs an exact value of k + 1 significant digits that ends in 5.
    let (wide, wide_exp) = sci_parts(&format!("{x:.k$e}"))?;
    if wide_exp != exp || !wide.ends_with('5') {
        return Some((digits, exp));
    }
    let (exact, _) = sci_parts(&format!("{x:.EXACT_PRECISION$e}"))?;
    let exact_tail = exact.get(wide.len()..)?;
    if exact.get(..wide.len())? != wide || exact_tail.bytes().any(|b| b != b'0') {
        return Some((digits, exp));
    }
    // The value is halfway between `lower` and `lower + 1` in the last digit.
    let lower = wide.get(..k)?;
    let last = lower.bytes().last()?;
    if last == b'9' {
        return Some((digits, exp));
    }
    // The ASCII code of a digit has the parity of the digit.
    let even = if last & 1 == 0 {
        lower.to_owned()
    } else {
        let mut upper = lower.get(..k.checked_sub(1)?)?.to_owned();
        upper.push(char::from(last.checked_add(1)?));
        upper
    };
    let reads_back = sci_text(&even, exp)?
        .parse::<f64>()
        .is_ok_and(|y| y.to_bits() == x.to_bits());
    if reads_back {
        Some((even, exp))
    } else {
        Some((digits, exp))
    }
}

/// Writes the ECMAScript form of the digits `d1..dk` times `10^(n-k)` (ECMA-262 `Number::toString`).
fn es_body(digits: &str, n: i32, out: &mut String) -> Option<()> {
    let k = i32::try_from(digits.len()).ok()?;
    if k <= n && n <= ES_MAX_PLAIN {
        out.push_str(digits);
        push_zeros(out, n.checked_sub(k)?);
    } else if 0 < n && n <= ES_MAX_PLAIN {
        let split = usize::try_from(n).ok()?;
        out.push_str(digits.get(..split)?);
        out.push('.');
        out.push_str(digits.get(split..)?);
    } else if (ES_MIN_PLAIN..=0).contains(&n) {
        out.push_str("0.");
        push_zeros(out, n.checked_neg()?);
        out.push_str(digits);
    } else {
        out.push_str(digits.get(..1)?);
        if k > 1 {
            out.push('.');
            out.push_str(digits.get(1..)?);
        }
        let e = n.checked_sub(1)?;
        out.push('e');
        out.push(if e < 0 { '-' } else { '+' });
        out.push_str(&e.unsigned_abs().to_string());
    }
    Some(())
}

/// Adds `count` zero digits. A negative count adds none.
fn push_zeros(out: &mut String, count: i32) {
    for _ in 0..count {
        out.push('0');
    }
}

/// Gives the offset after the run of ASCII digits that starts at `pos`.
fn skip_digits(bytes: &[u8], mut pos: usize) -> usize {
    while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        pos = pos.saturating_add(1);
    }
    pos
}

/// Gives the offset after one or more ASCII digits at `pos`.
fn need_digits(bytes: &[u8], pos: usize) -> Result<usize, JsonError> {
    match bytes.get(pos) {
        Some(b) if b.is_ascii_digit() => Ok(skip_digits(bytes, pos)),
        Some(_) => Err(JsonError::new(Code::Number, pos)),
        None => Err(JsonError::new(Code::Eof, pos)),
    }
}

/// Gives the end offset of the number lexeme that starts at `start`.
///
/// # Errors
///
/// Returns [`Code::Eof`] when the bytes end inside the lexeme.
/// Returns [`Code::Number`] at the first byte that breaks the grammar.
pub(crate) fn scan(bytes: &[u8], start: usize) -> Result<usize, JsonError> {
    let mut pos = start;
    if bytes.get(pos) == Some(&b'-') {
        pos = pos.saturating_add(1);
    }
    match bytes.get(pos) {
        Some(b'0') => {
            pos = pos.saturating_add(1);
            if bytes.get(pos).is_some_and(u8::is_ascii_digit) {
                return Err(JsonError::new(Code::Number, pos));
            }
        }
        Some(b'1'..=b'9') => pos = skip_digits(bytes, pos),
        Some(_) => return Err(JsonError::new(Code::Number, pos)),
        None => return Err(JsonError::new(Code::Eof, pos)),
    }
    if bytes.get(pos) == Some(&b'.') {
        pos = need_digits(bytes, pos.saturating_add(1))?;
    }
    if matches!(bytes.get(pos), Some(b'e' | b'E')) {
        pos = pos.saturating_add(1);
        if matches!(bytes.get(pos), Some(b'+' | b'-')) {
            pos = pos.saturating_add(1);
        }
        pos = need_digits(bytes, pos)?;
    }
    Ok(pos)
}

impl FromStr for Number {
    type Err = JsonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Makes `From` impls for integer types.
macro_rules! from_int {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for Number {
                fn from(value: $ty) -> Self {
                    Self(value.to_string())
                }
            }
        )*
    };
}

from_int!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);
