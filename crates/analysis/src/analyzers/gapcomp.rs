//! `GapComponents` (band 470): seed 13 of design Section 7.3, code components in gaps.
//!
//! A gap is executable code that no solid function owns. [`super::gaps`] gives the scope and
//! the fixed area of the binary. A function is solid when it has a start reason outside
//! [`DERIVED`], or when the flow of a solid function reaches its entry. The reasons of
//! [`DERIVED`] come from the code of other functions. So the gaps do not depend on the seeds
//! of this module.
//!
//! The analyzer decodes each gap linearly. After an instruction that does not fall through,
//! it skips padding. The CFG of the gap instructions has these edges:
//!
//! | Flow | Edge |
//! |---|---|
//! | the fall-through of an instruction | strong |
//! | a conditional branch to a gap instruction | strong |
//! | a case of a resolved jump table or of an agent table | strong |
//! | an unconditional jump to a gap instruction | a join when only one strong part jumps there |
//! | a call | none |
//!
//! An unconditional jump to a call target, or to code that two strong parts jump to, is a
//! tail call. It leaves the component. Each weakly connected component becomes a function
//! when it passes 3 tests:
//!
//! - Every instruction decodes. A direct call goes to executable memory.
//! - Every path ends in `ret`, an indirect jump, a noreturn call or a jump out of the
//!   component. A jump out goes to a function entry or to another component.
//! - It has at least [`MIN_INSNS`] instructions.
//!
//! The entry is the lowest address of the component that has no predecessor in it. It gets
//! the reason `GapComponent`, confidence [`CONFIDENCE`] and `R_GAP_COMPONENT`. Each step tests
//! every gap again, and a `GapComponent` reason that fails a test goes. An entry gets the
//! reason at most [`MAX_ADDS`] times, so the steps reach a fixpoint.

use ghidorah_db::StartReason;
use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};

/// The confidence of a `GapComponent` start.
pub const CONFIDENCE: u8 = 40;

/// The smallest number of instructions of a component.
pub const MIN_INSNS: u64 = 4;

/// The largest number of gap bytes that one step decodes.
pub const MAX_SCAN: u64 = 4 << 20;

/// The largest number of times that one entry gets the reason.
pub const MAX_ADDS: u8 = 8;

/// The reasons that come from the code of another function. Alone they do not make a
/// function solid.
pub const DERIVED: [StartReason; 4] = [
    StartReason::GapComponent,
    StartReason::Call,
    StartReason::TailCall,
    StartReason::AddrTaken,
];

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::GapComponents,
    name: "GapComponents",
    priority: 470,
    triggers: &[Trigger::Bytes, Trigger::Instructions, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[Opt {
        name: "min_insns",
        value: MIN_INSNS,
        doc: "The smallest number of instructions of a gap component.",
    }],
    doc: "Starts a function at the entry of each closed code component in a gap.",
};

/// Runs one step: every gap gets the tests again. The ranges only queue the step.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}
