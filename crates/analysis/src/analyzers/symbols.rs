//! `Symbols` (band 110): a function at each function symbol with a size (design Section 7.3).
//!
//! An `STT_FUNC` or `STT_GNU_IFUNC` symbol with a size above 0 at a defined, executable
//! address gets the start reason `Symbol` with confidence 100 and `R_SYMBOL_FUNC`. Its size
//! gives a declared extent: the flow of another function stops there.

use ghidorah_base::{Address, Range};
use ghidorah_db::{FactKey, Program, StartReason, SymKind as DbKind};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::elf::consts::SHN_UNDEF;
use ghidorah_loader::{Sym, SymKind, SymTable};

use crate::code::is_exec;
use crate::ctx::AnalysisCtx;
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Step, Trigger};
use crate::why::{Rule, Why};

/// The spec.
pub const SPEC: AnalyzerSpec = AnalyzerSpec {
    id: AnalyzerId::Symbols,
    name: "Symbols",
    priority: 110,
    triggers: &[Trigger::Bytes],
    version: 1,
    grain: Grain::Whole,
    options: &[],
    doc: "Starts a function at each function symbol with a size.",
};

/// Gives the key of the base-layer symbol of `sym`: the function symbol with its name, else
/// the primary symbol at its address.
fn premise(program: &Program, sym: &Sym) -> Option<FactKey> {
    let addr = Address::ram(sym.addr);
    let name = sym.name.as_str();
    let symbols = program.base().symbols();
    symbols
        .at(addr)
        .find(|s| name == Some(s.name.value.as_str()))
        .or_else(|| symbols.primary(addr).filter(|s| s.kind == DbKind::Function))
        .map(|s| FactKey::Symbol(addr, s.key))
}

/// Gives the extent of a function symbol with a size above 0.
fn extent(sym: &Sym) -> Option<Range> {
    let defined =
        !matches!(sym.table, SymTable::Symtab | SymTable::Dynsym) || sym.shndx != SHN_UNDEF;
    let func = matches!(sym.kind, SymKind::Func | SymKind::Ifunc);
    if !defined || !func {
        return None;
    }
    Range::with_len(sym.addr, sym.size)
}

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    let mut work = 1u64;
    for sym in &program.binary().symbols {
        work = work.saturating_add(1);
        let Some(range) = extent(sym) else {
            continue;
        };
        if !ranges.contains(sym.addr) || !is_exec(program, sym.addr) {
            continue;
        }
        let why = Why::new(
            Rule::SymbolFunc,
            premise(program, sym).into_iter().collect(),
        );
        let _ = ctx.add_reason(sym.addr, StartReason::Symbol, 100, why);
        ctx.add_extent(sym.addr, range);
    }
    Step { work }
}
