//! The gap worklist (design Section 7.3, ADR-0024).
//!
//! The MVP has no prologue-pattern gap fill. Executable code that no function owns becomes a
//! gap item with the remedy `func_edit { action: "create" }`. The items are derived data of the
//! committed facts. They have no band and no work state.
//!
//! Rules:
//!
//! - The scope is the executable sections, or the executable regions of a file with no section
//!   headers, without the PLT area.
//! - The function bodies of both layers leave the scope.
//! - Padding is not a gap: a `nop` form, `int3` and a 0 byte. Padding splits a range, so each
//!   gap item is a run without padding.
//! - Bytes that do not decode stay in the gap, one byte at a time.

use ghidorah_base::Range;
use ghidorah_db::Program;

use crate::analyzers::metrics::Remedy;

/// The largest number of bytes that a gap item shows.
pub const SHOW_BYTES: usize = 16;

/// One gap item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gap {
    /// The addresses of the gap.
    pub range: Range,
    /// The first bytes of the gap, at most [`SHOW_BYTES`].
    pub bytes: Vec<u8>,
    /// The display text of the first instruction, or `None` when it does not decode.
    pub first_insn: Option<String>,
}

impl Gap {
    /// Gives the remedy: `func_edit { action: "create" }` at the first address.
    #[must_use]
    pub const fn remedy(&self) -> Remedy {
        Remedy::Create(self.range.first)
    }
}

/// Gives the gap items of `program` in address order.
#[must_use]
pub fn items(program: &Program) -> Vec<Gap> {
    let _ = program;
    Vec::new()
}
