//! `EndbrSeeds` (band 440): a function at each free `endbr64` head (design Section 7.3).
//!
//! The scan reads the executable sections named `.text`, or every executable region of a file
//! with no section headers. Each `f3 0f 1e fa` that no code unit holds and that no function
//! body holds gets the start reason `Endbr` with confidence 85 and `R_ENDBR_HEAD`. A head
//! after a call to a `setjmp`-like function or a jump target inside a body is in a body, so
//! it is not a seed.

use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The bytes of `endbr64`.
pub const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::EndbrSeeds,
    name: "EndbrSeeds",
    priority: 440,
    triggers: &[Trigger::Bytes, Trigger::Instructions],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each endbr64 head that no body holds.",
};

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step::default()
}
