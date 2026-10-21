//! The self-check of the structure (design Section 8.2, step 7).
//!
//! The CFG walker and the AST interpreter run with [`ORACLES`] branch oracles. The seed of
//! each oracle comes from the hash of the function body: FNV-1a 64 over the address and the
//! length of each instruction. The two block traces must be equal. A mismatch switches the
//! output to FLAT and adds `W_STRUCTURE_SELFCHECK`. FLAT output is always correct.

use ghidorah_base::{Fnv1a64, WarningCode};

use crate::interp_ast::{Seeded, cfg_trace, tree_trace};
use crate::structure::{FlatReason, Mode};
use crate::view::View;
use crate::{Decomp, Warning};

/// The number of branch oracles.
pub const ORACLES: u64 = 8;

/// The largest block count of one trace.
pub const TRACE_LIMIT: usize = 4_096;

/// The step between the seeds of two oracles: the 64-bit golden ratio.
const SEED_STEP: u64 = 0x9e37_79b9_7f4a_7c15;

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
            Self::Ok => "ok",
            Self::Repaired => "repaired",
        }
    }
}

/// Gives the body hash of a view: FNV-1a 64 over the entry, then the address and the length
/// of each instruction.
#[must_use]
pub fn body_hash(view: &View) -> u64 {
    let mut h = Fnv1a64::new();
    h.write(&view.entry.to_le_bytes());
    for (addr, len) in &view.insns {
        h.write(&addr.to_le_bytes());
        h.write_u8(*len);
    }
    h.finish()
}

/// Gives the block limit of the traces of a shape: four visits of each node, within
/// [`TRACE_LIMIT`].
fn limit(view: &View) -> usize {
    view.shape.len().saturating_mul(4).clamp(64, TRACE_LIMIT)
}

/// Tells if the tree of `decomp` gives the block traces of its shape under each oracle.
#[must_use]
pub fn traces_match(decomp: &Decomp) -> bool {
    let shape = &decomp.view.shape;
    let base = body_hash(&decomp.view);
    let limit = limit(&decomp.view);
    (0..ORACLES).all(|k| {
        let oracle = Seeded(base ^ k.wrapping_mul(SEED_STEP));
        cfg_trace(shape, &oracle, limit) == tree_trace(&decomp.tree, shape, &oracle, limit)
    })
}

/// Runs the self-check on `decomp`. A mismatch gives FLAT output with
/// `W_STRUCTURE_SELFCHECK`.
pub fn check(decomp: &mut Decomp) -> Validation {
    if traces_match(decomp) {
        return Validation::Ok;
    }
    decomp.tree = crate::flat::tree(&decomp.view.shape);
    decomp.mode = Mode::Flat(FlatReason::SelfCheck);
    decomp.warnings.push(Warning {
        code: WarningCode::StructureSelfcheck,
        at: decomp.view.entry,
    });
    decomp.warnings.sort_unstable();
    decomp.warnings.dedup();
    Validation::Repaired
}
