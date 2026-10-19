//! `PdataSeeds` (band 155): a function at each `.pdata` start of a PE file (design Sections 4.14
//! and 7.3).
//!
//! The `BeginAddress` of each `RUNTIME_FUNCTION` entry that is not a fragment gets the start
//! reason `Pdata` with confidence 95 and `R_PDATA_START`. The entry range gives a declared
//! extent. A `CHAININFO` fragment is no start: its range becomes a `Cold` part of the function at
//! the root of its chain, when the flow of that function reaches it. The analyzer adds no fact
//! for another format.

use ghidorah_base::{Limits, Range};
use ghidorah_db::StartReason;
use ghidorah_kernel::RangeSet;
use ghidorah_loader::Format;
use ghidorah_loader::pe::pdata::chain_root;

use crate::code::is_exec;
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

/// The confidence of a `Pdata` start (design Section 7.3).
pub const CONFIDENCE: u8 = 95;

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::PdataSeeds,
    name: "PdataSeeds",
    priority: 155,
    triggers: &[Trigger::Bytes],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each .pdata entry of a PE file that is not a fragment.",
};

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    if program.meta().format != Format::Pe32Plus {
        return Step { work: 1 };
    }
    let base = program.meta().image_base;
    let mut work = 1u64;
    for rf in &program.binary().pdata {
        work = work.saturating_add(1);
        let (Some(begin), Some(last)) = (
            base.checked_add(u64::from(rf.begin)),
            rf.end
                .checked_sub(1)
                .and_then(|e| base.checked_add(u64::from(e))),
        ) else {
            continue;
        };
        if !ranges.contains(begin) || !is_exec(program, begin) {
            continue;
        }
        if rf.fragment {
            let root = chain_root(program.mem(), base, rf.unwind, &Limits::DEFAULT);
            let parent = root
                .ok()
                .flatten()
                .and_then(|r| base.checked_add(u64::from(r)));
            if let Some(parent) = parent.filter(|p| *p != begin)
                && ctx.ir().parts.get(&begin) != Some(&parent)
            {
                ctx.ir_mut().parts.insert(begin, parent);
            }
            continue;
        }
        let why = Why::bare(Rule::PdataStart);
        let _ = ctx.add_reason(begin, StartReason::Pdata, CONFIDENCE, why);
        if let Some(extent) = Range::new(begin, last) {
            ctx.add_extent(begin, extent);
        }
    }
    Step { work }
}
