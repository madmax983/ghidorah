//! `Symbols` (band 110): a function at each function symbol with a size (design Section 7.3).
//!
//! An `STT_FUNC` or `STT_GNU_IFUNC` symbol with a size above 0 at a defined, executable
//! address gets the start reason `Symbol` with confidence 100 and `R_SYMBOL_FUNC`. Its size
//! gives a declared extent: the flow of another function stops there.
//!
//! The order of the symbols at one address in the table changes no fact. The first alias in
//! the alias order gives the premise of the reason. The alias order puts a global alias
//! first, then a weak one, then a local one. Inside one binding, it uses the byte order of
//! the name. The program takes its primary symbol by the same rule. The extents of the
//! aliases go in range order.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, Range};
use ghidorah_db::{FactKey, Program, StartReason, SymKind as DbKind};
use ghidorah_kernel::RangeSet;
use ghidorah_loader::elf::consts::SHN_UNDEF;
use ghidorah_loader::{Sym, SymBind, SymKind, SymTable};

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

/// Gives the order key of an alias (see the module doc).
fn alias_key(sym: &Sym) -> (u8, &[u8]) {
    let bind = match sym.bind {
        SymBind::Global | SymBind::Unique => 0,
        SymBind::Weak => 1,
        SymBind::Other(_) => 2,
        SymBind::Local => 3,
    };
    (bind, sym.name.as_bytes())
}

/// Runs one step over `ranges`.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    let mut work = 1u64;
    let mut aliases: BTreeMap<u64, Vec<&Sym>> = BTreeMap::new();
    for sym in &program.binary().symbols {
        work = work.saturating_add(1);
        if extent(sym).is_some() && ranges.contains(sym.addr) && is_exec(program, sym.addr) {
            aliases.entry(sym.addr).or_default().push(sym);
        }
    }
    for (addr, mut syms) in aliases {
        syms.sort_by(|a, b| alias_key(a).cmp(&alias_key(b)));
        let Some(first) = syms.first() else {
            continue;
        };
        let why = Why::new(
            Rule::SymbolFunc,
            premise(program, first).into_iter().collect(),
        );
        let _ = ctx.add_reason(addr, StartReason::Symbol, 100, why);
        let extents: BTreeSet<Range> = syms.iter().filter_map(|s| extent(s)).collect();
        for range in extents {
            ctx.add_extent(addr, range);
        }
    }
    Step { work }
}
