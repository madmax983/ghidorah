//! Fixed-point rates in thousandths. Output has no floats (design Section 10.11).

use std::fmt;

use ghidorah_json::{Number, Value};

/// A rate or a metric value in thousandths: 1000 is 1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Milli(pub u64);

impl Milli {
    /// The value 1.0.
    pub const ONE: Self = Self(1000);

    /// Gives `num / den` in thousandths, rounded down. A zero `den` gives 1.0, because an
    /// empty set has no failure.
    #[must_use]
    pub fn ratio(num: u64, den: u64) -> Self {
        if den == 0 {
            return Self::ONE;
        }
        Self(num.saturating_mul(1000) / den)
    }

    /// Parses a decimal text such as `0.70`, `1.00` or `3` with at most three decimals.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (int, frac) = text.split_once('.').unwrap_or((text, ""));
        if int.is_empty() || frac.len() > 3 || !int.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let whole: u64 = int.parse().ok()?;
        let mut part: u64 = if frac.is_empty() {
            0
        } else {
            frac.parse().ok()?
        };
        for _ in frac.len()..3 {
            part = part.checked_mul(10)?;
        }
        whole.checked_mul(1000)?.checked_add(part).map(Self)
    }

    /// Gives the value of a JSON number, or `None` for another value.
    #[must_use]
    pub fn of_json(value: &Value) -> Option<Self> {
        match value {
            Value::Number(n) => Self::parse(n.as_str()),
            _ => None,
        }
    }

    /// Gives the JSON number with three decimals, for example `0.739`.
    #[must_use]
    pub fn to_json(self) -> Value {
        Number::parse(&self.to_string()).map_or(Value::Null, Value::Number)
    }
}

impl fmt::Display for Milli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:03}", self.0 / 1000, self.0 % 1000)
    }
}

#[cfg(test)]
mod tests;
