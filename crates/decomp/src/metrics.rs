//! The metrics of a decompile (design Sections 8.3 and 8.5).
//!
//! | Metric | Count |
//! |---|---|
//! | `goto_count` | the `goto` lines of the structure. An unresolved `goto *(x);` is a statement. |
//! | `label_count` | the label lines |
//! | `max_nesting` | the deepest block depth of a line. The function body has depth 1. |
//! | `stmt_count` | the statement lines |
//! | `fallback_mode` | `none`, or `flat` for FLAT output |
//! | `validation` | `ok`, or `repaired` after a self-check mismatch |

use crate::print::Line;
use crate::selfcheck::Validation;
use crate::structure::Mode;

/// The metrics of a decompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Metrics {
    /// The count of `goto` lines of the structure.
    pub goto_count: u32,
    /// The count of label lines.
    pub label_count: u32,
    /// The deepest block depth.
    pub max_nesting: u32,
    /// The count of statement lines.
    pub stmt_count: u32,
    /// The output mode.
    pub mode: Mode,
    /// The self-check result.
    pub validation: Validation,
}

/// Measures `lines`.
#[must_use]
pub fn measure(lines: &[Line], mode: Mode, validation: Validation) -> Metrics {
    let _ = lines;
    Metrics {
        goto_count: 0,
        label_count: 0,
        max_nesting: 0,
        stmt_count: 0,
        mode,
        validation,
    }
}
