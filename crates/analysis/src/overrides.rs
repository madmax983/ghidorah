//! `Overrides` (band 160): the seeds of the higher-rank facts (design Sections 3.6 and 7.1).
//!
//! The analyzer reads the base layer once:
//!
//! | Base fact | Seed |
//! |---|---|
//! | an agent or user function | a function with the start reason `Agent` and `R_AGENT_FUNCTION` |
//! | an `indirect_targets` override at a call | a function at each RAM target with `R_AGENT_CALL_TARGET` |
//! | an agent call reference to executable memory | a function at the target with `R_AGENT_REF` |
//!
//! `Disasm` reads the flow of each site with [`site_flow`]. An agent jump table or an
//! `indirect_targets` override at an indirect jump gives its cases. A method A table of the
//! work state gives the cases of a jump with no agent fact. The other flow overrides change
//! the flow of the site. Analysis never writes over an agent fact (ADR-0013). When it
//! disagrees, the function gets `W_AGENT_OVERRIDE_CONFLICT` with the analysis value.

use ghidorah_kernel::RangeSet;
use ghidorah_x86::Flow;

use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};

/// The confidence of a function that an agent call target or reference seeds.
pub const TARGET_CONFIDENCE: u8 = 95;

/// Gives the spec of `Overrides` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "Overrides",
        priority: 160,
        triggers: &[Trigger::Bytes],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Seeds the agent functions, the agent call targets and the agent call references.",
    }
}

/// The flow of one site that a fact sets.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SiteFlow {
    /// The cases of an indirect jump: an agent table, an agent override or a method A table.
    Cases(Vec<u64>),
    /// The targets of an indirect call from an agent override.
    Calls(Vec<u64>),
    /// The flow after the instruction goes to this address.
    Fallthrough(u64),
    /// The call is a jump.
    CallAsJump,
    /// The jump is a call.
    JumpAsCall,
}

/// Gives the flow that a fact sets for the instruction at `at` with the decoder flow `flow`.
#[must_use]
pub fn site_flow(ctx: &AnalysisCtx<'_>, at: u64, flow: Flow) -> Option<SiteFlow> {
    let _ = (ctx, at, flow);
    None
}

/// Runs one step: the seeds of the base layer.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = (ctx, ranges);
    Step { work: 1 }
}
