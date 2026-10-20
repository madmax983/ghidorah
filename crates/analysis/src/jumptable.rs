//! `JumpTables` (band 410): jump tables by method A (design Section 7.8).
//!
//! [`method_a`] finds the guard `cmp idx, N; ja default` (or `jae`, `jbe`, `jb`) in the block
//! of the indirect jump or up a chain of blocks with one predecessor. Then it runs the backward
//! slice of the jump target with the index pinned to each value `0..=N`. The slice has at most
//! [`MAX_SLICE_OPS`] ops and [`MAX_SLICE_BLOCKS`] blocks, and it stops at calls. The loads read
//! the read-only image. The forms are the 4-byte PIC table (`movsxd; add`) and the 8-byte
//! absolute table (`jmp [T + idx*8]`). The first load gives the table base and the entry size.
//!
//! | Result | Record |
//! |---|---|
//! | every target is an executable address that the caller accepts | a resolved table with method `a` |
//! | the guard, the slice or a target fails | an unresolved table and `W_JUMPTABLE_UNRESOLVED` |
//! | an agent table at the jump | no record; a different method A result gives `W_AGENT_OVERRIDE_CONFLICT` |
//! | an agent `indirect_targets` override at the jump | no record |
//!
//! A new or changed table queues `Disasm` for its function, so the descent follows the cases.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{Address, Fuel, JumpTableId, Range};
use ghidorah_db::{FactKey, FlowKind, FlowOverride, JtMethod, JumpTable, Program};
use ghidorah_ir::local::{self, Pin, Query, Target};
use ghidorah_ir::{Arg, Loc, Memory, Node, Opc};
use ghidorah_kernel::RangeSet;

use crate::code::{decode_at, is_exec, slot_of};
use crate::ctx::AnalysisCtx;
use crate::fir::{FuncIr, Image};
use crate::irfacts::{Conflict, TableRec, func_key, work_ir};
use crate::registry::AnalyzerId;
use crate::spec::{AnalyzerSpec, Grain, Opt, Step, Trigger};
use crate::why::{Rule, Why};

/// The largest number of ops of a slice.
pub const MAX_SLICE_OPS: usize = 50;

/// The largest number of blocks of a slice.
pub const MAX_SLICE_BLOCKS: usize = 4;

/// The largest number of entries of a table.
pub const MAX_CASES: u64 = 1024;

/// Gives the spec of `JumpTables` with the registry ID `id`.
#[must_use]
pub const fn spec(id: AnalyzerId) -> AnalyzerSpec {
    AnalyzerSpec {
        id,
        name: "JumpTables",
        priority: 410,
        triggers: &[Trigger::Instructions],
        version: 1,
        grain: Grain::Whole,
        options: &[
            Opt {
                name: "max_slice_ops",
                value: 50,
                doc: "The largest number of ops of a slice.",
            },
            Opt {
                name: "max_cases",
                value: MAX_CASES,
                doc: "The largest number of entries of a table.",
            },
        ],
        doc: "Resolves the jump tables of the indirect jumps by method A.",
    }
}

/// A resolved table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Resolved {
    /// The address of the first entry.
    pub base: Option<u64>,
    /// The entry size in bytes: 4 or 8.
    pub entry_size: u8,
    /// The case targets in case order.
    pub targets: Vec<u64>,
}

/// Why method A fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Failure {
    /// The address is not an indirect jump of the function IR.
    NoSite,
    /// No guard bounds the index.
    NoGuard,
    /// The slice has no value for an index.
    Slice {
        /// The index.
        idx: u64,
    },
    /// A target is not an accepted executable address.
    Target {
        /// The target.
        target: u64,
    },
    /// The guard gives more than [`MAX_CASES`] entries.
    TooMany {
        /// The entry count.
        count: u64,
    },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSite => f.write_str("The address is not an indirect jump."),
            Self::NoGuard => f.write_str("No guard bounds the index."),
            Self::Slice { idx } => write!(f, "The slice has no target for the index {idx}."),
            Self::Target { target } => write!(f, "The target {target:#x} is not accepted."),
            Self::TooMany { count } => write!(f, "The table has {count} entries."),
        }
    }
}

/// Resolves the jump table of the indirect jump at `site` in `fir`. `accept` tells if a
/// target is an executable address of the function region. The loads read `mem`.
///
/// # Errors
///
/// Returns the [`Failure`] of the first step that fails.
pub fn method_a(
    fir: &FuncIr,
    mem: &dyn Memory,
    site: u64,
    accept: &dyn Fn(u64) -> bool,
    fuel: &mut Fuel,
) -> Result<Resolved, Failure> {
    let jump = fir.find_op(site, Opc::JumpInd).ok_or(Failure::NoSite)?;
    let guard = guard(fir, site).ok_or(Failure::NoGuard)?;
    let count = guard
        .max
        .checked_add(1)
        .ok_or(Failure::TooMany { count: u64::MAX })?;
    if count > MAX_CASES {
        return Err(Failure::TooMany { count });
    }
    let scope = fir.scope(mem);
    let mut out = Resolved {
        base: None,
        entry_size: 0,
        targets: Vec::new(),
    };
    for idx in 0..count {
        let query = Query {
            op: jump,
            target: Target::Arg(0),
            pin: Some(Pin {
                op: guard.pin,
                loc: guard.loc,
                value: idx,
            }),
            max_ops: MAX_SLICE_OPS,
            max_blocks: MAX_SLICE_BLOCKS,
        };
        let walk = local::eval(&scope, &query, fuel);
        let target = walk.value.value().ok_or(Failure::Slice { idx })?;
        if !accept(target) {
            return Err(Failure::Target { target });
        }
        if idx == 0
            && let Some((base, size)) = walk.loads.first()
        {
            out.base = Some(*base);
            out.entry_size = *size;
        }
        out.targets.push(target);
    }
    Ok(out)
}

/// The guard of a table: the largest index, the index location and the op that reads it.
struct Guard {
    max: u64,
    loc: Loc,
    pin: u32,
    info: GuardInfo,
}

/// The guard `cmp idx, N; ja default` of a jump table, as the decompiler shows it in a
/// `switch` with a `default` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuardInfo {
    /// The address of the conditional branch of the guard.
    pub branch: u64,
    /// The index of the compare op of the branch. The op keeps its index in L1.
    pub cmp: u32,
    /// The input of the compare that is the table index: 0 or 1.
    pub operand: u8,
    /// The largest index: the table has `max + 1` entries.
    pub max: u64,
    /// The address of the block that the branch takes for an index above `max`.
    pub default: u64,
}

/// Finds the guard of the indirect jump at `site`. The guard is the compare of a conditional
/// branch up the chain of single predecessors. The jump is on its in-range side.
fn guard(fir: &FuncIr, site: u64) -> Option<Guard> {
    let preds = fir.body.cfg.preds();
    let mut node = fir.block_at(site)?;
    for _ in 1..MAX_SLICE_BLOCKS {
        let [pred] = preds.get(node.index())?.as_slice() else {
            return None;
        };
        let start = *fir.starts.get(node.index())?;
        if let Some(g) = branch_guard(fir, *pred, start) {
            return Some(g);
        }
        node = *pred;
    }
    None
}

/// Gives the guard of the indirect jump at `site` of `fir`, or `None` when no guard bounds the
/// index (see [`method_a`]).
#[must_use]
pub fn guard_info(fir: &FuncIr, site: u64) -> Option<GuardInfo> {
    guard(fir, site).map(|g| g.info)
}

/// Reads the guard of the branch at the end of the block `pred` when the flow goes to the
/// block at `start`.
fn branch_guard(fir: &FuncIr, pred: Node, start: u64) -> Option<Guard> {
    let block = fir.body.blocks.get(pred.index())?;
    let last = block.first.checked_add(block.count)?.checked_sub(1)?;
    let span = fir.arena.insns().get(usize::try_from(last).ok()?)?;
    let ops = fir.arena.span_ops(span)?;
    let branch = ops.iter().find(|o| o.opc == Opc::CJump)?;
    let target = branch.a[1].as_k()?;
    let taken = target == start;
    let cmp_index = fir.arena.def_of(branch.a[0].as_v()?)?;
    let cmp = fir.arena.op(cmp_index)?;
    let (operand, max) = match (cmp.opc, cmp.a[0].as_k(), cmp.a[1].as_k(), taken) {
        (Opc::ULt, Some(n), None, false) => (1u8, n),
        (Opc::ULe, Some(n), None, false) => (1, n.checked_sub(1)?),
        (Opc::ULe, None, Some(n), true) => (0, n),
        (Opc::ULt, None, Some(n), true) => (0, n.checked_sub(1)?),
        _ => return None,
    };
    let x = *cmp.a.get(usize::from(operand))?;
    let (loc, pin) = index_loc(fir, x)?;
    let default = if taken {
        fir.body
            .cfg
            .succs(pred)
            .iter()
            .filter_map(|n| fir.starts.get(n.index()).copied())
            .find(|&a| a != start)?
    } else {
        target
    };
    let info = GuardInfo {
        branch: span.addr,
        cmp: cmp_index,
        operand,
        max,
        default,
    };
    Some(Guard {
        max,
        loc,
        pin,
        info,
    })
}

/// Gives the location that an index value reads and the op index of that read: a `Get`,
/// through `Trunc`, `ZExt` and `SExt`.
fn index_loc(fir: &FuncIr, x: Arg) -> Option<(Loc, u32)> {
    let mut arg = x;
    for _ in 0..4 {
        let index = fir.arena.def_of(arg.as_v()?)?;
        let op = fir.arena.op(index)?;
        match op.opc {
            Opc::Get => return Some((op.a[0].as_loc()?, index)),
            Opc::Trunc | Opc::ZExt | Opc::SExt => arg = op.a[0],
            _ => return None,
        }
    }
    None
}

/// Gives the indirect jumps of `fir` that do not go through an import slot, in address order.
/// A jump through a slot loads its target from a constant address.
#[must_use]
pub fn sites(fir: &FuncIr) -> Vec<u64> {
    let mut out = Vec::new();
    for (at, u) in &fir.units {
        if u.flow != FlowKind::IJmp {
            continue;
        }
        let Some(op) = fir.find_op(*at, Opc::JumpInd).and_then(|i| fir.arena.op(i)) else {
            continue;
        };
        let slot = op.a[0]
            .as_v()
            .and_then(|v| fir.arena.def_of(v))
            .and_then(|d| fir.arena.op(d))
            .is_some_and(|d| d.opc == Opc::Load && d.a[0].as_k().is_some());
        if !slot {
            out.push(*at);
        }
    }
    out
}

/// The fuel of method A at one jump. A fixed amount keeps each step independent of the slices.
const SITE_FUEL: u64 = 1_000_000;

/// Gives the remedy of a conflict with an agent table, with the analysis count.
fn conflict_remedy(count: usize) -> String {
    format!("func_edit {{ action: \"set_jumptable\", count: {count} }}")
}

/// Runs one step over `ranges`: each function that the ranges touch gets its tables again.
pub fn run(ctx: &mut AnalysisCtx<'_>, ranges: &RangeSet) -> Step {
    let program = ctx.program();
    if !program.meta().arch.is_x86_64() {
        return Step { work: 1 };
    }
    let mut work = 1u64;
    for entry in ctx.touching(ranges) {
        work = work.saturating_add(1);
        let sites = indirect_jumps(ctx, entry);
        let mut tables = BTreeMap::new();
        let mut conflicts = BTreeSet::new();
        if !sites.is_empty()
            && let Ok(ir) = work_ir(ctx, entry, &mut Fuel::new(SITE_FUEL))
        {
            work = work.saturating_add(u64::try_from(ir.units.len()).unwrap_or(u64::MAX));
            let region = |at: u64| program.mem().region_at(at).map(|r| r.va);
            let accept = |t: u64| {
                is_exec(program, t)
                    && region(t) == region(entry)
                    && ctx.foreign_extent(entry, t).is_none()
            };
            for site in sites {
                let result = method_a(
                    &ir,
                    &Image(program),
                    site,
                    &accept,
                    &mut Fuel::new(SITE_FUEL),
                );
                match agent_targets(program, site) {
                    Some(agent) => {
                        if let Ok(r) = &result
                            && r.targets != agent
                        {
                            conflicts.insert(Conflict {
                                at: site,
                                remedy: conflict_remedy(r.targets.len()),
                            });
                        }
                    }
                    None => {
                        tables.insert(site, record(entry, site, result));
                    }
                }
            }
        }
        update(ctx, entry, tables, conflicts);
    }
    Step { work }
}

/// Gives the record of a method A result at `site` in the function `entry`.
fn record(entry: u64, site: u64, result: Result<Resolved, Failure>) -> TableRec {
    let table = match result {
        Ok(r) => JumpTable {
            base: r.base.map(Address::ram),
            entry_size: r.entry_size,
            count: u16::try_from(r.targets.len()).unwrap_or(u16::MAX),
            targets: r.targets.into_iter().map(Address::ram).collect(),
            method: JtMethod::A,
            resolved: true,
        },
        Err(_) => JumpTable {
            base: None,
            entry_size: 0,
            count: 0,
            targets: Vec::new(),
            method: JtMethod::A,
            resolved: false,
        },
    };
    let why = Why::new(
        Rule::JumptableSlice,
        vec![FactKey::CodeUnit(site), func_key(entry)],
    );
    TableRec {
        owner: entry,
        table,
        why,
    }
}

/// Puts the tables and the conflicts of the function `entry` in place of its old ones. A
/// change of the cases queues `Disasm` for the function.
fn update(
    ctx: &mut AnalysisCtx<'_>,
    entry: u64,
    tables: BTreeMap<u64, TableRec>,
    conflicts: BTreeSet<Conflict>,
) {
    let old: BTreeMap<u64, TableRec> = ctx
        .ir()
        .tables
        .iter()
        .filter(|(_, r)| r.owner == entry)
        .map(|(s, r)| (*s, r.clone()))
        .collect();
    let old_conflicts = ctx.ir().conflicts.get(&entry).cloned().unwrap_or_default();
    if old == tables && old_conflicts == conflicts {
        return;
    }
    let cases_changed = old.len() != tables.len()
        || old
            .iter()
            .any(|(s, r)| tables.get(s).map(|t| &t.table.targets) != Some(&r.table.targets));
    let ir = ctx.ir_mut();
    ir.tables.retain(|_, r| r.owner != entry);
    ir.tables.extend(tables);
    if conflicts.is_empty() {
        ir.conflicts.remove(&entry);
    } else {
        ir.conflicts.insert(entry, conflicts);
    }
    if cases_changed {
        ctx.requeue(AnalyzerId::Disasm, Range::single(entry));
    }
}

/// Gives the indirect jumps of the function `entry` in the work state that do not go through
/// an import slot.
fn indirect_jumps(ctx: &AnalysisCtx<'_>, entry: u64) -> Vec<u64> {
    let program = ctx.program();
    ctx.units_of(entry)
        .into_iter()
        .filter(|(_, u)| u.flow == FlowKind::IJmp)
        .filter(|(at, _)| decode_at(program, *at).as_ref().and_then(slot_of).is_none())
        .map(|(at, _)| at)
        .collect()
}

/// Gives the case targets of an agent fact at `site`: an agent table or an
/// `indirect_targets` override.
fn agent_targets(program: &Program, site: u64) -> Option<Vec<u64>> {
    let addr = Address::ram(site);
    if let Some(FlowOverride::IndirectTargets(t)) =
        program.base().overrides().get(addr).map(|f| &f.value)
    {
        return Some(t.iter().filter(|a| a.is_ram()).map(|a| a.off).collect());
    }
    program.base().jumptables().get(JumpTableId(addr)).map(|t| {
        t.value
            .targets
            .iter()
            .filter(|a| a.is_ram())
            .map(|a| a.off)
            .collect()
    })
}
