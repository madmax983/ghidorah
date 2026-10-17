//! The JSON number: a raw lexeme that matches the RFC 8259 grammar.

use std::fmt;
use std::str::FromStr;

use crate::error::{Code, JsonError};

/// A JSON number that keeps its raw lexeme.
///
/// The lexeme always matches the RFC 8259 grammar
/// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
/// So `9007199254740993` keeps all its digits, and the writer never emits `NaN` or `inf`.
/// Two numbers are equal when their lexemes are equal: `1.0` and `1` are different numbers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        let _ = text;
        Err(JsonError::new(Code::Number, 0))
    }

    /// Makes a number from a finite `f64`.
    ///
    /// The lexeme is the shortest text that reads back as the same `f64`.
    /// `NaN` and the infinities give `None`, so no writer can emit them.
    #[must_use]
    pub fn from_f64(value: f64) -> Option<Self> {
        let _ = value;
        None
    }

    /// Gives the raw lexeme.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Tells if the lexeme has no fraction part and no exponent part.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        false
    }

    /// Gives the value as `u64` when the lexeme is an integer in range.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        None
    }

    /// Gives the value as `i64` when the lexeme is an integer in range.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        None
    }

    /// Gives the nearest `f64`, or `None` when the value is outside the `f64` range.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        None
    }

    /// Gives the RFC 8785 (JCS) text of the number, or `None` when it is outside the `f64` range.
    ///
    /// JCS writes the nearest `f64` in the ECMAScript form, for example `1e+21` and `0.000001`.
    /// So an integer above 2^53 can lose its low digits in this form.
    #[must_use]
    pub fn to_jcs(&self) -> Option<String> {
        None
    }
}

/// Gives the end offset of the number lexeme that starts at `start`.
///
/// # Errors
///
/// Returns [`Code::Eof`] when the bytes end inside the lexeme.
/// Returns [`Code::Number`] at the first byte that breaks the grammar.
pub(crate) fn scan(bytes: &[u8], start: usize) -> Result<usize, JsonError> {
    let _ = bytes;
    Err(JsonError::new(Code::Number, start))
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
                    let _ = value;
                    Self(String::new())
                }
            }
        )*
    };
}

from_int!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);
