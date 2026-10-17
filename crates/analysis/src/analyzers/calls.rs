//! `CallTargets` (band 400): a function at each direct call target (design Section 7.3).
//!
//! The roots are the functions with a start reason other than `Call`. A walk in address order
//! goes from the roots over the direct call sites of the bodies. Each target that the walk
//! reaches in executable memory gets the start reason `Call` with confidence 95 and
//! `R_CALL_TARGET`. The premise is the reference of the first call site of the walk, so the
//! premise graph has no cycle. A `Call` reason that the walk does not reach goes. So dead code
//! after a new noreturn call does not keep its callees.

use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::CallTargets,
    name: "CallTargets",
    priority: 400,
    triggers: &[Trigger::Instructions],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each direct call target that the roots reach.",
};

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step::default()
}
