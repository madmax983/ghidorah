//! `FdeSeeds` (band 150): a function at each FDE start of an ELF file (design Section 7.3).
//!
//! The PC begin of each FDE in an executable region gets the start reason `Fde` with
//! confidence 90 and `R_FDE_START`. The PC range gives a declared extent. An FDE in the PLT
//! area describes the stub table, so it is not a seed. The analyzer adds no fact for another
//! format.

use ghidorah_db::{FactKey, StartReason};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::Format;

use crate::code::is_exec;
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

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
    let program = ctx.program();
    if program.meta().format != Format::Elf64Le {
        return Step { work: 1 };
    }
    let mut work = 1u64;
    for fde in &program.binary().fdes {
        work = work.saturating_add(1);
        let at = fde.range.first;
        if !ranges.contains(at) || !is_exec(program, at) || ctx.in_plt(at) {
            continue;
        }
        let why = Why::new(Rule::FdeStart, vec![FactKey::Fde(at)]);
        let _ = ctx.add_reason(at, StartReason::Fde, 90, why);
        ctx.add_extent(at, fde.range);
    }
    Step { work }
}
