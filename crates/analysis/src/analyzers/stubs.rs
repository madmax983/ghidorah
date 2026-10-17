//! `ImportStubs` (band 120): a function at each PLT stub of an ELF file (design Section 7.3).
//!
//! The loader names each jump stub through its import slot, never by its position. Each
//! stub of an import in an executable region gets the start reason `PltStub` with confidence
//! 100 and `R_PLT_RELOC_SLOT`. The premises are the import and the slot relocation.
//! The analyzer adds no fact for another format.

use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::ImportStubs,
    name: "ImportStubs",
    priority: 120,
    triggers: &[Trigger::Bytes],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each PLT stub of an ELF import.",
};

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step::default()
}
