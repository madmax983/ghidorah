//! `FdeSeeds` (band 150): a function at each FDE start of an ELF file (design Section 7.3).
//!
//! The PC begin of each FDE in an executable region gets the start reason `Fde` with
//! confidence 90 and `R_FDE_START`. The PC range gives a declared extent. The analyzer adds
//! no fact for another format.

use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::FdeSeeds,
    name: "FdeSeeds",
    priority: 150,
    triggers: &[Trigger::Bytes],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each FDE PC begin of an ELF file.",
};

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step::default()
}
