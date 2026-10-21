//! One gate violation.

use std::fmt;

use crate::json::Value;

/// One violation that a gate finds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The file, relative to the workspace root.
    pub path: String,
    /// The 1-based line, or 0 when the finding applies to the full file.
    pub line: usize,
    /// The rule ID, for example `AC-012`.
    pub rule: String,
    /// What is wrong.
    pub detail: String,
}

impl Finding {
    /// Makes a finding.
    pub fn new(
        rule: impl Into<String>,
        path: impl Into<String>,
        line: usize,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            line,
            rule: rule.into(),
            detail: detail.into(),
        }
    }

    /// Gives the finding as a JSON object.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::object([
            ("path", Value::from(self.path.as_str())),
            ("line", Value::from(self.line)),
            ("rule", Value::from(self.rule.as_str())),
            ("detail", Value::from(self.detail.as_str())),
        ])
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: {}: {}",
            self.path, self.line, self.rule, self.detail
        )
    }
}
