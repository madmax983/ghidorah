//! `Symbols` (band 110): a function at each function symbol with a size (design Section 7.3).
//!
//! An `STT_FUNC` or `STT_GNU_IFUNC` symbol with a size above 0 at a defined, executable
//! address gets the start reason `Symbol` with confidence 100 and `R_SYMBOL_FUNC`. Its size
//! gives a declared extent: the flow of another function stops there.

use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::Symbols,
    name: "Symbols",
    priority: 110,
    triggers: &[Trigger::Bytes],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each function symbol with a size.",
};

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step::default()
}
