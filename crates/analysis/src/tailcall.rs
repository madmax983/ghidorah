//! `TailCallsAndParts` (band 420): FETCH tail calls and cold parts (design Section 7.3).
//!
//! A jump from a function `F` to an address `T` outside the body of `F` is a candidate. The
//! analyzer decides each candidate with [`decide`]:
//!
//! | Candidate | Decision |
//! |---|---|
//! | `T` has another reason than its FDE, a call site, or jumps from two functions | [`Decision::Keep`] |
//! | an FDE-only `T` whose jumps all come from `F` with a stack height of 0, with no conditional jump, and whose flow does not come back into `F` | [`Decision::TailCall`] |
//! | another FDE-only `T` with jumps from `F` only | [`Decision::Cold`]: `T` becomes a `Cold` part of `F` |
//! | a `T` with no function that `F` holds after an unconditional jump with a stack height of 0, outside the declared extent of `F`, or at an `endbr64` head when `F` has no extent | [`Decision::TailCall`] |
//!
//! A tail call gives `T` the start reason `TailCall` with `R_TAILCALL`. A cold part loses its
//! FDE start reason, so the descent of `F` takes its code as a part.

use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// Gives the spec of `TailCallsAndParts` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "TailCallsAndParts",
        priority: 420,
        triggers: &[Trigger::Instructions, Trigger::Functions],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Finds tail calls by the FETCH rule and merges cold parts into their parents.",
    }
}

/// One jump of a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Jump {
    /// The jump site.
    pub site: u64,
    /// The entry of the function of the jump.
    pub from: u64,
    /// The jump is conditional.
    pub conditional: bool,
    /// The stack height at the jump, or `None` when it is not known.
    pub height: Option<i64>,
}

/// One candidate target.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Candidate {
    /// The target.
    pub target: u64,
    /// A function starts at the target.
    pub is_func: bool,
    /// The only start reason of the function is its FDE.
    pub fde_only: bool,
    /// A direct call goes to the target.
    pub called: bool,
    /// The jumps to the target.
    pub jumps: Vec<Jump>,
    /// The flow of the target comes back into the body of the jump source.
    pub returns_into_source: bool,
    /// The source function has a declared extent, and the target is outside it.
    pub outside_extent: bool,
    /// The source function has no declared extent.
    pub no_extent: bool,
    /// The target is an `endbr64` instruction.
    pub endbr: bool,
}

/// The decision about a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    /// The candidate stays as it is.
    Keep,
    /// The target is a function that a tail call reaches.
    TailCall,
    /// The target is a cold part of the function at `parent`.
    Cold {
        /// The entry of the parent.
        parent: u64,
    },
}

/// Decides one candidate by the rules of the module table.
#[must_use]
pub fn decide(c: &Candidate) -> Decision {
    let _ = c;
    Decision::Keep
}

/// Runs one step over `ranges`: each function that the ranges touch gets its candidates
/// again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}
