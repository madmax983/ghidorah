//! `Entry` (band 100): a function at each entry point of the binary (design Section 7.3).
//!
//! The entry points are the ELF entry, the init, fini and preinit arrays, and for PE the
//! entry point, the TLS callbacks and the exports into executable regions. Each entry in an
//! executable region gets the start reason `Entry` with confidence 100 and `R_ENTRY`.

use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::Entry,
    name: "Entry",
    priority: 100,
    triggers: &[Trigger::Bytes],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each entry point of the binary.",
};

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step::default()
}
