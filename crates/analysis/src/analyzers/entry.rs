//! `Entry` (band 100): a function at each entry point of the binary (design Section 7.3).
//!
//! The ELF entry points are the entry and the init, fini and preinit arrays. The PE entry
//! points are the entry, the TLS callbacks and the exports into executable regions. Each entry
//! in an executable region gets the start reason `Entry` with confidence 100 and `R_ENTRY`.

use ghidorah_db::{FactKey, StartReason};
use ghidorah_kernel::RangeSet;

use crate::code::is_exec;
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

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
    let program = ctx.program();
    let mut work = 1u64;
    for e in &program.binary().entry_points {
        work = work.saturating_add(1);
        if !ranges.contains(e.addr) || !is_exec(program, e.addr) {
            continue;
        }
        let why = Why::new(Rule::Entry, vec![FactKey::Entry(e.addr)]);
        let _ = ctx.add_reason(e.addr, StartReason::Entry, 100, why);
    }
    Step { work }
}
