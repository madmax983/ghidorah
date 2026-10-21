//! `MainDiscovery` (band 430): `main` from the first argument of `__libc_start_main` (design
//! Section 7.11). ELF only.
//!
//! [`find`] looks at each call in the function at the ELF entry. A call to the PLT stub of
//! `__libc_start_main`, or a call through its import slot, is the start call. Block-local
//! evaluation (design Section 6.6) gives `rdi` before it. An address in executable memory is
//! `main`: it gets the start reason `Main` with confidence 95 and the name `main` with the
//! source `Analysis`.

use ghidorah_base::{Address, Fuel, ImportId};
use ghidorah_db::{FactKey, FlowKind, Program, StartReason};
use ghidorah_ir::{Loc, Opc, local};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::{EntryKind, Format};

use crate::code::{decode_at, is_exec, slot_of};
use crate::ctx::AnalysisCtx;
use crate::fir::{FuncIr, Image};
use crate::irfacts::{func_key, work_ir};
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};
use crate::work::import_slots;

/// The name of the start function of the C library.
pub const LIBC_START: &str = "__libc_start_main";

/// The confidence of a `Main` start (design Section 7.3).
pub const CONFIDENCE: u8 = 95;

/// Gives the spec of `MainDiscovery` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "MainDiscovery",
        priority: 430,
        triggers: &[Trigger::Instructions, Trigger::Functions],
        version: 1,
        grain: Grain::Whole,
        options: &[],
        doc: "Finds main from the first argument of __libc_start_main.",
    }
}

/// One start call: the call site and the value of `rdi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StartCall {
    /// The call site.
    pub site: u64,
    /// The address of `main`.
    pub main: u64,
}

/// Finds the start call in `fir`, the IR of the function at the ELF entry.
#[must_use]
pub fn find(program: &Program, fir: &FuncIr, fuel: &mut Fuel) -> Option<StartCall> {
    let slots = import_slots(program);
    let image = Image(program);
    let scope = fir.scope(&image);
    for (at, u) in &fir.units {
        let opc = match u.flow {
            FlowKind::Call => Opc::Call,
            FlowKind::ICall => Opc::CallInd,
            _ => continue,
        };
        let Some(insn) = decode_at(program, *at) else {
            continue;
        };
        let callee = match u.flow {
            FlowKind::Call => insn.target().and_then(|t| stub_import(program, t)),
            _ => slot_of(&insn).and_then(|s| slots.get(&s).map(|(id, _)| id.clone())),
        };
        if callee.is_none_or(|id| id.name() != Some(LIBC_START)) {
            continue;
        }
        let op = fir.find_op(*at, opc)?;
        let main = local::value_at(&scope, op, Loc::RDI, fuel).value()?;
        return is_exec(program, main).then_some(StartCall { site: *at, main });
    }
    None
}

/// Gives the import of the PLT stub at `stub`.
fn stub_import(program: &Program, stub: u64) -> Option<ImportId> {
    program
        .imports()
        .values()
        .find(|r| r.stub == Some(Address::ram(stub)))
        .map(|r| r.id.clone())
}

/// Gives the address of the ELF entry of `program`.
fn elf_entry(program: &Program) -> Option<u64> {
    if program.meta().format != Format::Elf64Le {
        return None;
    }
    program
        .binary()
        .entry_points
        .iter()
        .find(|e| e.kind == EntryKind::Entry)
        .map(|e| e.addr)
}

/// The fuel of one start-call search.
const FIND_FUEL: u64 = 1_000_000;

/// Runs one step: the function at the ELF entry gets its start call again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let _ = ranges;
    let program = ctx.program();
    let found = elf_entry(program)
        .filter(|e| ctx.is_entry(*e))
        .and_then(|entry| {
            let mut fuel = Fuel::new(FIND_FUEL);
            let ir = work_ir(ctx, entry, &mut fuel).ok()?;
            let call = find(program, &ir, &mut fuel)?;
            let why = Why::new(
                Rule::MainFromLibcStart,
                vec![FactKey::CodeUnit(call.site), func_key(entry)],
            );
            Some((call.main, why))
        });
    if ctx.ir().main == found {
        return Step { work: 2 };
    }
    if let Some((old, _)) = ctx.ir().main.clone() {
        let _ = ctx.remove_reason(old, StartReason::Main);
    }
    if let Some((main, why)) = &found {
        let _ = ctx.add_reason(*main, StartReason::Main, CONFIDENCE, why.clone());
    }
    ctx.ir_mut().main = found;
    Step { work: 2 }
}
