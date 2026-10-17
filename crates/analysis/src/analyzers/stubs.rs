//! `ImportStubs` (band 120): a function at each PLT stub of an ELF file (design Section 7.3).
//!
//! The loader names each jump stub through its import slot, never by its position. Each
//! stub of an import in an executable region gets the start reason `PltStub` with confidence
//! 100 and `R_PLT_RELOC_SLOT`. The premises are the import and the slot relocation.
//! The analyzer adds no fact for another format.

use std::collections::BTreeSet;

use ghidorah_base::Address;
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
    let program = ctx.program();
    if program.meta().format != Format::Elf64Le {
        return Step { work: 1 };
    }
    let relocs: BTreeSet<u64> = program.binary().relocs.iter().map(|r| r.offset).collect();
    let mut work = 1u64;
    for row in program.imports().values() {
        work = work.saturating_add(1);
        let Some(stub) = row.stub.filter(Address::is_ram) else {
            continue;
        };
        if !ranges.contains(stub.off) || !is_exec(program, stub.off) {
            continue;
        }
        let mut premises = vec![FactKey::Import(row.id.clone())];
        if let Some(slot) = row.slot.filter(|s| relocs.contains(&s.off)) {
            premises.push(FactKey::Reloc(slot.off));
        }
        let why = Why::new(Rule::PltRelocSlot, premises);
        let _ = ctx.add_reason(stub.off, StartReason::PltStub, 100, why);
    }
    Step { work }
}
