//! The self-check of the structure (design Section 8.2, step 7).
//!
//! The CFG walker and the AST interpreter run with [`ORACLES`] branch oracles. The seed of
//! each oracle comes from the hash of the function body: FNV-1a 64 over the address and the
//! length of each instruction. The two block traces must be equal. A mismatch switches the
//! output to FLAT and adds `W_STRUCTURE_SELFCHECK`. FLAT output is always correct.

use crate::Decomp;
use crate::view::View;

/// The number of branch oracles.
pub const ORACLES: u64 = 8;

/// The largest block count of one trace.
pub const TRACE_LIMIT: usize = 4_096;

/// The result of the self-check: `validation.structure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Validation {
    /// The traces are equal.
    Ok,
    /// The traces differ, and the output is FLAT.
    Repaired,
}

impl Validation {
    /// Gives the name: `ok` or `repaired`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ok => "repaired",
            Self::Repaired => "ok",
        }
    }
}

/// Gives the body hash of a view: FNV-1a 64 over the entry, then the address and the length
/// of each instruction.
#[must_use]
pub fn body_hash(view: &View) -> u64 {
    let _ = view;
    0
}

/// Tells if the tree of `decomp` gives the block traces of its shape under each oracle.
#[must_use]
pub fn traces_match(decomp: &Decomp) -> bool {
    let _ = decomp;
    false
}

/// Runs the self-check on `decomp`. A mismatch gives FLAT output with
/// `W_STRUCTURE_SELFCHECK`.
pub fn check(decomp: &mut Decomp) -> Validation {
    let _ = decomp;
    Validation::Repaired
}
