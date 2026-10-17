//! `Disasm` (band 300): recursive descent from each function entry (design Sections 7.3, 7.7).
//!
//! The descent follows fall-through, branch and call edges. It stops at these addresses:
//!
//! | Address | Result |
//! |---|---|
//! | the entry of another function | an exit: a tail call or a fall into that function |
//! | an address in the declared extent of another function | an exit |
//! | code of a function with a lower entry | an exit: the lower entry keeps shared code |
//! | an address outside executable memory, bad bytes, a jump into an instruction | `unknown` |
//! | the address after a call to a noreturn function | no edge: the site gets [`UNIT_NORETURN_CALL`](crate::ctx::UNIT_NORETURN_CALL) |
//!
//! Each instruction becomes a code unit with `R_DISASM_FLOW`. Each direct call and jump gives
//! a flow reference with `R_FLOW_REF`. A call or a jump through an import slot gives a
//! reference to the EXTERNAL address of the import.

use ghidorah_kernel::RangeSet;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};

/// The largest number of instructions in one function body.
pub const MAX_INSNS: u64 = 100_000;

/// The largest number of body changes of one function. Then its body stays.
pub const MAX_CHANGES: u64 = 64;

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::Disasm,
    name: "Disasm",
    priority: 300,
    triggers: &[Trigger::Functions, Trigger::FunctionModifiers],
    version: 1,
    grain: Grain::Range,
    options: &[
        Opt {
            name: "max_insns",
            value: MAX_INSNS,
            doc: "The largest number of instructions in one function body.",
        },
        Opt {
            name: "max_changes",
            value: MAX_CHANGES,
            doc: "The largest number of body changes of one function.",
        },
    ],
    doc: "Decodes the body of each function by recursive descent.",
};

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step::default()
}
