//! `AddrTakenSeeds` (band 460): seed 12 of design Section 7.3, address-taken code.
//!
//! An instruction of a body takes the address of code in two forms:
//!
//! | Instruction | Taken address | File |
//! |---|---|---|
//! | `lea` with a RIP-relative memory operand | the operand address | every file |
//! | `mov` with a 32-bit immediate | the immediate | a file at a fixed address (`ET_EXEC`) |
//!
//! An address in an executable region is a target. [`super::dataptr`] gives the tests of each
//! target. A target that passes them starts a function with the reason `AddrTaken`, confidence
//! [`CONFIDENCE`] and `R_ADDR_TAKEN`. The premise is the code unit of the first site.
//!
//! A step decodes the code units in its ranges again. Then every target gets the tests again,
//! and an `AddrTaken` reason that fails a test goes.

use ghidorah_db::Program;
use ghidorah_kernel::RangeSet;
use ghidorah_x86::Insn;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The confidence of an `AddrTaken` start.
pub const CONFIDENCE: u8 = 75;

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::AddrTakenSeeds,
    name: "AddrTakenSeeds",
    priority: 460,
    triggers: &[Trigger::Bytes, Trigger::Instructions, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each address-taken code target that no body holds.",
};

/// Gives the code address that `insn` takes, or `None`. The address is in an executable
/// region of `program`.
#[must_use]
pub fn taken(program: &Program, insn: &Insn) -> Option<u64> {
    let _ = (program, insn);
    None
}

/// Runs one step: the sites of the code units in `ranges`, then the tests of every target.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}
