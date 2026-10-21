//! `IatThunks` (band 405): the IAT thunks of a PE file (design Sections 4.11 and 7.3).
//!
//! A function whose first instruction is `jmp qword ptr [rip+disp32]` through the IAT slot of
//! an import is a thunk. The function gets the flag `thunk` and the import name, and the
//! why-record `R_IAT_THUNK` links it to the import. The name of an import by ordinal is
//! `<dll>!#<ordinal>`. The loader does not scan for thunks, because the same bytes can be a
//! tail call inside a function. The analyzer adds no fact for another format.

use ghidorah_base::{Address, FuncId, ImportId};
use ghidorah_db::FactKey;
use ghidorah_kernel::RangeSet;
use ghidorah_loader::Format;
use ghidorah_x86::Flow;

use crate::code::{decode_at, slot_of};
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::IatThunks,
    name: "IatThunks",
    priority: 405,
    triggers: &[Trigger::Instructions, Trigger::Functions],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Names each PE function whose first instruction jumps through an IAT slot.",
};

/// One IAT thunk: the import and the function name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThunkRec {
    /// The import of the slot.
    pub import: ImportId,
    /// The function name: the import name, or `<dll>!#<ordinal>`.
    pub name: String,
    /// The why-record.
    pub why: Why,
}

/// Gives the function name of an import: its name, or `<dll>!#<ordinal>`.
#[must_use]
pub fn import_name(id: &ImportId) -> String {
    match (id.name(), id.lib(), id.ordinal()) {
        (Some(name), _, _) => name.to_owned(),
        (None, Some(dll), Some(ordinal)) => format!("{dll}!#{ordinal}"),
        _ => id.to_string(),
    }
}

/// Gives the thunk record of the function `entry`, or `None` when it is no thunk.
fn thunk_at(ctx: &AnalysisCtx<'_>, entry: u64) -> Option<ThunkRec> {
    let insn = decode_at(ctx.program(), entry)?;
    if insn.flow() != Flow::IJmp {
        return None;
    }
    let slot = slot_of(&insn)?;
    let (import, _) = ctx.slot_target(slot)?;
    let premises = vec![
        FactKey::Func(FuncId(Address::ram(entry))),
        FactKey::Import(import.clone()),
    ];
    Some(ThunkRec {
        import: import.clone(),
        name: import_name(import),
        why: Why::new(Rule::IatThunk, premises),
    })
}

/// Runs one step over `ranges`: each function entry in the ranges is tested again, and a
/// record of a lost function goes.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    if ctx.program().meta().format != Format::Pe32Plus {
        return Step { work: 1 };
    }
    let mut work = 1u64;
    for entry in ctx.entries() {
        if !ranges.contains(entry) {
            continue;
        }
        work = work.saturating_add(1);
        let rec = thunk_at(ctx, entry);
        if ctx.ir().thunks.get(&entry) != rec.as_ref() {
            match rec {
                Some(r) => {
                    ctx.ir_mut().thunks.insert(entry, r);
                }
                None => {
                    ctx.ir_mut().thunks.remove(&entry);
                }
            }
        }
    }
    let gone: Vec<u64> = ctx
        .ir()
        .thunks
        .keys()
        .copied()
        .filter(|e| !ctx.is_entry(*e))
        .collect();
    if !gone.is_empty() {
        let ir = ctx.ir_mut();
        for e in gone {
            ir.thunks.remove(&e);
        }
    }
    Step { work }
}
