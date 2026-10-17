//! Parser failures and their conversion to [`CDiag`].

use ghidorah_base::DiagCode;

use super::{CDiag, CParseError, MAX_SNIPPET, Span};

/// The bytes of a snippet before the error place.
const SNIPPET_BEFORE: usize = 40;

/// An internal parser failure: a code, a byte range and the repair data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fail {
    code: DiagCode,
    byte: usize,
    len: usize,
    expected: Vec<String>,
    candidates: Vec<String>,
    hint: Option<String>,
}

impl Fail {
    /// Makes a failure at `byte` with the length `len`.
    pub(crate) const fn new(code: DiagCode, byte: usize, len: usize) -> Self {
        Self {
            code,
            byte,
            len,
            expected: Vec::new(),
            candidates: Vec::new(),
            hint: None,
        }
    }

    /// Sets the expected items.
    pub(crate) fn expected(mut self, items: &[&str]) -> Self {
        self.expected = items.iter().map(ToString::to_string).collect();
        self
    }

    /// Sets the candidates.
    pub(crate) fn candidates(mut self, names: Vec<String>) -> Self {
        self.candidates = names;
        self
    }

    /// Sets the hint.
    pub(crate) fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Makes the diagnostic of the failure in `text`.
    pub(crate) fn diag(self, text: &str) -> CDiag {
        let byte = self.byte.min(text.len());
        let prefix = text.get(..byte).unwrap_or("");
        let line_start = prefix.rfind('\n').map_or(0, |i| i.saturating_add(1));
        let line = prefix
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
            .saturating_add(1);
        let col = text
            .get(line_start..byte)
            .map_or(0, |s| s.chars().count())
            .saturating_add(1);
        let line_end = text
            .get(byte..)
            .and_then(|r| r.find('\n'))
            .map_or(text.len(), |n| byte.saturating_add(n));
        let mut start = line_start.max(byte.saturating_sub(SNIPPET_BEFORE));
        while !text.is_char_boundary(start) {
            start = start.saturating_add(1);
        }
        let mut end = line_end.min(start.saturating_add(MAX_SNIPPET));
        while !text.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        let snippet = text.get(start..end).unwrap_or("").trim_end().to_string();
        let to_u32 = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);
        let hint = self
            .hint
            .unwrap_or_else(|| self.code.info().hint.to_string());
        CDiag {
            code: self.code,
            at: Span {
                line: to_u32(line),
                col: to_u32(col),
                byte: to_u32(byte),
                len: to_u32(self.len),
            },
            snippet,
            expected: self.expected,
            candidates: self.candidates,
            hint,
        }
    }

    /// Makes the parse error of the failure in `text`.
    pub(crate) fn error(self, text: &str) -> CParseError {
        CParseError {
            errors: vec![self.diag(text)],
        }
    }
}
