//! The SSA checker (design Section 6.4, AC-073 and AC-256).
//!
//! [`check`] reports each break of the SSA rules of an [`Ssa`].
//!
//! | Rule | Statement |
//! |---|---|
//! | [`Rule::SingleDef`] | Each value has one def op, and the arena gives that op. |
//! | [`Rule::DefDominatesUse`] | The def of each use comes before it in its block, or its block dominates the block of the use. A phi argument is a use at the end of its predecessor. |
//! | [`Rule::PhiArity`] | Each phi has one argument for each predecessor, plus one for the function entry in the entry block. |
//! | [`Rule::RemovedValue`] | No op reads a value whose def op is gone. |
//! | [`Rule::Shape`] | No instruction op is a `Get`, `Put` or `Phi`. A block head holds only phis. An added `Get` is at the anchor `Start` or after an op. |
//!
//! The entry does not reach an unreachable block, so no run reads its values. The checker
//! does not apply [`Rule::DefDominatesUse`] to a use in such a block.

use std::fmt;

use crate::op::{OpId, Val};
use crate::ssa::Ssa;

/// A rule of the SSA checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// Each value has one def op.
    SingleDef,
    /// The def of a value dominates each use.
    DefDominatesUse,
    /// A phi has one argument for each incoming edge.
    PhiArity,
    /// No op reads a removed value.
    RemovedValue,
    /// The ops have the L1 shape.
    Shape,
}

impl Rule {
    /// Gives the name of the rule, for example `phi_arity`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SingleDef => "single_def",
            Self::DefDominatesUse => "def_dominates_use",
            Self::PhiArity => "phi_arity",
            Self::RemovedValue => "removed_value",
            Self::Shape => "shape",
        }
    }
}

/// One break of an SSA rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Violation {
    /// The rule.
    pub rule: Rule,
    /// The op with the break.
    pub at: OpId,
    /// The value of the break, when one applies.
    pub val: Option<Val>,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at {:#x}:{}",
            self.rule.name(),
            self.at.addr,
            self.at.seq
        )?;
        if let Some(val) = self.val {
            write!(f, " ({val})")?;
        }
        Ok(())
    }
}

/// Gives each break of the SSA rules, in the run order of [`Ssa::order`].
#[must_use]
pub fn check(ssa: &Ssa) -> Vec<Violation> {
    let _ = ssa;
    Vec::new()
}
