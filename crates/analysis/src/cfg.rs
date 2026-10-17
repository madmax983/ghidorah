//! The CFG of one function (design Section 7.4).
//!
//! [`build`] derives the CFG from the published code units of a function body. It decodes
//! each branch again for its target. The block ID is the start address (`bb:0x..`).
//!
//! Leaders: the entry, the branch targets in the body, the instruction after a branch, a
//! call or a stop, the start of each body range and each jump-table target.
//!
//! | Last instruction | Edges |
//! |---|---|
//! | plain, before a leader | `fallthrough` |
//! | `jmp` | `branch` in the body, else `tailcall` |
//! | `jcc` | `cond_true` to the target, `cond_false` to the next instruction |
//! | `call` | `call_return`, except after a noreturn callee (AC-080a) |
//! | indirect `jmp` | `switch_case(i)` for a resolved jump table, `tailcall` through an import slot, else `indirect_unresolved` |
//! | `ret`, trap | none |
//!
//! A `fallthrough` or `cond_false` edge out of the body is a `tailcall` edge.
//!
//! [`check`] tests the invariants of AC-083: the blocks are contiguous and disjoint, each
//! internal edge ends at a block start, each block is reachable from the entry or from a
//! jump-table case, and no instruction is in two blocks.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{Address, FuncId, JumpTableId};
use ghidorah_db::{CodeUnit, FlowKind, Program};
use ghidorah_kernel::RangeSet;

use crate::code::{decode_at, slot_of};
use crate::ctx::UNIT_NORETURN_CALL;
use crate::work::{SlotImport, import_slots};

/// The kind of a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeKind {
    /// Execution continues at the next block.
    Fallthrough,
    /// A direct jump in the body.
    Branch,
    /// The taken edge of a conditional branch.
    CondTrue,
    /// The fall-through edge of a conditional branch.
    CondFalse,
    /// Case `i` of a jump table.
    SwitchCase(u16),
    /// The return of a call that returns.
    CallReturn,
    /// A flow to code outside the body.
    TailCall,
    /// An indirect jump with no known target.
    IndirectUnresolved,
}

impl EdgeKind {
    /// Gives the output name, for example `cond_true` or `switch_case`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fallthrough => "fallthrough",
            Self::Branch => "branch",
            Self::CondTrue => "cond_true",
            Self::CondFalse => "cond_false",
            Self::SwitchCase(_) => "switch_case",
            Self::CallReturn => "call_return",
            Self::TailCall => "tailcall",
            Self::IndirectUnresolved => "indirect_unresolved",
        }
    }

    /// Tells if the edge stays in the body.
    #[must_use]
    pub const fn is_internal(self) -> bool {
        !matches!(self, Self::TailCall | Self::IndirectUnresolved)
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One basic block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The first address: the block ID.
    pub start: u64,
    /// The instructions: start and length, in address order.
    pub insns: Vec<(u64, u8)>,
}

impl Block {
    /// Gives the address after the last instruction.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.insns
            .last()
            .map_or(self.start, |(at, len)| at.saturating_add(u64::from(*len)))
    }
}

/// One CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Edge {
    /// The start of the source block.
    pub from: u64,
    /// The target, or `None` for an unresolved indirect jump.
    pub to: Option<Address>,
    /// The kind.
    pub kind: EdgeKind,
}

/// The CFG of one function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncCfg {
    /// The function.
    pub func: FuncId,
    /// The blocks in address order.
    pub blocks: Vec<Block>,
    /// The edges in source order, then in the order of the last instruction.
    pub edges: Vec<Edge>,
}

/// A broken CFG invariant (AC-083).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CfgViolation {
    /// The CFG has no block at the entry.
    NoEntryBlock,
    /// A block has a gap between two instructions.
    Gap {
        /// The block.
        block: u64,
    },
    /// Two blocks overlap, or two blocks hold one instruction.
    Overlap {
        /// The second block.
        block: u64,
    },
    /// An internal edge ends where no block starts.
    EdgeTarget {
        /// The source block.
        from: u64,
        /// The target.
        to: u64,
    },
    /// No path from the entry or from a jump-table case reaches the block.
    Unreachable {
        /// The block.
        block: u64,
    },
}

/// One code unit of a body: the length, the flow kind and the site flags.
type Unit = (u8, FlowKind, u8);

/// Gives the code units of `body`. A unit of the analysis layer wins over the base layer.
fn units(program: &Program, body: &RangeSet) -> BTreeMap<u64, Unit> {
    let mut out = BTreeMap::new();
    for r in body.ranges() {
        for t in [program.base(), program.analysis()] {
            for (at, unit) in t.listing().units_in(*r) {
                let CodeUnit::Insn { len, flow, flags } = unit;
                out.insert(at, (*len, *flow, *flags));
            }
        }
    }
    out
}

/// Tells if a call returns: no noreturn flag on the site and no noreturn callee.
fn returns(program: &Program, flags: u8, target: Option<u64>) -> bool {
    if flags & UNIT_NORETURN_CALL != 0 {
        return false;
    }
    let callee = target.and_then(|t| program.func(FuncId(Address::ram(t))));
    !callee.and_then(|f| f.noreturn).is_some_and(|n| n.value)
}

/// The edges of one function as the build makes them.
struct Edges<'a> {
    program: &'a Program,
    starts: &'a BTreeMap<u64, Unit>,
    slots: Option<BTreeMap<u64, SlotImport>>,
    out: Vec<Edge>,
}

impl Edges<'_> {
    /// Adds an edge from `from` to `to`. A target outside the body gives a `tailcall` edge.
    fn to(&mut self, from: u64, to: u64, kind: EdgeKind) {
        let kind = if self.starts.contains_key(&to) {
            kind
        } else {
            EdgeKind::TailCall
        };
        self.out.push(Edge {
            from,
            to: Some(Address::ram(to)),
            kind,
        });
    }

    /// Adds the edges of an indirect jump at `at` in the block `from`.
    fn indirect(&mut self, from: u64, at: u64) {
        let program = self.program;
        let table = program
            .jump_table(JumpTableId(Address::ram(at)))
            .filter(|t| t.value.resolved);
        if let Some(table) = table {
            for (i, t) in table.value.targets.iter().enumerate() {
                let case = EdgeKind::SwitchCase(u16::try_from(i).unwrap_or(u16::MAX));
                if t.is_ram() {
                    self.to(from, t.off, case);
                } else {
                    self.out.push(Edge {
                        from,
                        to: Some(*t),
                        kind: EdgeKind::TailCall,
                    });
                }
            }
            return;
        }
        let slot = decode_at(program, at).as_ref().and_then(slot_of);
        let slots = self.slots.get_or_insert_with(|| import_slots(program));
        let ext = slot.and_then(|s| slots.get(&s)).map(|(_, ext)| *ext);
        self.out.push(Edge {
            from,
            to: ext,
            kind: if ext.is_some() {
                EdgeKind::TailCall
            } else {
                EdgeKind::IndirectUnresolved
            },
        });
    }

    /// Adds the edges of the block `from` whose last unit is `at`.
    fn block(&mut self, from: u64, at: u64, unit: Unit) {
        let (len, flow, flags) = unit;
        let Some(next) = at.checked_add(u64::from(len)) else {
            return;
        };
        let target = || decode_at(self.program, at).and_then(|i| i.target());
        match flow {
            FlowKind::Seq => self.to(from, next, EdgeKind::Fallthrough),
            FlowKind::Jmp => match target() {
                Some(t) => self.to(from, t, EdgeKind::Branch),
                None => self.indirect(from, at),
            },
            FlowKind::Jcc => {
                if let Some(t) = target() {
                    self.to(from, t, EdgeKind::CondTrue);
                }
                self.to(from, next, EdgeKind::CondFalse);
            }
            FlowKind::Call | FlowKind::ICall => {
                let callee = if flow == FlowKind::Call {
                    target()
                } else {
                    None
                };
                if returns(self.program, flags, callee) {
                    self.to(from, next, EdgeKind::CallReturn);
                }
            }
            FlowKind::IJmp => self.indirect(from, at),
            FlowKind::Ret | FlowKind::Trap => {}
        }
    }
}

/// Gives the leaders of a body: the entry, the targets in the body, the unit after each flow
/// change and each jump-table target.
fn leaders(program: &Program, entry: u64, units: &BTreeMap<u64, Unit>) -> BTreeSet<u64> {
    let mut out = BTreeSet::from([entry]);
    for (at, (len, flow, _)) in units {
        if *flow == FlowKind::Seq {
            continue;
        }
        if let Some(next) = at.checked_add(u64::from(*len)) {
            out.insert(next);
        }
        if matches!(flow, FlowKind::Jmp | FlowKind::Jcc)
            && let Some(t) = decode_at(program, *at).and_then(|i| i.target())
        {
            out.insert(t);
        }
        if *flow == FlowKind::IJmp
            && let Some(table) = program
                .jump_table(JumpTableId(Address::ram(*at)))
                .filter(|t| t.value.resolved)
        {
            out.extend(
                table
                    .value
                    .targets
                    .iter()
                    .filter(|t| t.is_ram())
                    .map(|t| t.off),
            );
        }
    }
    out
}

/// Builds the CFG of the function `func`. Gives `None` when the program has no such function.
#[must_use]
pub fn build(program: &Program, func: FuncId) -> Option<FuncCfg> {
    let view = program.func(func)?;
    let units = units(program, &view.func.body);
    let leaders = leaders(program, func.0.off, &units);
    let mut blocks: Vec<Block> = Vec::new();
    let mut end: Option<u64> = None;
    for (at, (len, _, _)) in &units {
        if leaders.contains(at) || end != Some(*at) || blocks.is_empty() {
            blocks.push(Block {
                start: *at,
                insns: Vec::new(),
            });
        }
        if let Some(b) = blocks.last_mut() {
            b.insns.push((*at, *len));
        }
        end = at.checked_add(u64::from(*len));
    }
    let mut edges = Edges {
        program,
        starts: &units,
        slots: None,
        out: Vec::new(),
    };
    for b in &blocks {
        if let Some((at, _)) = b.insns.last()
            && let Some(unit) = units.get(at)
        {
            edges.block(b.start, *at, *unit);
        }
    }
    Some(FuncCfg {
        func,
        blocks,
        edges: edges.out,
    })
}

/// Checks the invariants of AC-083. Gives the violations in block order.
#[must_use]
pub fn check(cfg: &FuncCfg) -> Vec<CfgViolation> {
    let mut out = Vec::new();
    let entry = cfg.func.0.off;
    if !cfg.blocks.iter().any(|b| b.start == entry) {
        out.push(CfgViolation::NoEntryBlock);
        return out;
    }
    let mut last_end: Option<u64> = None;
    for b in &cfg.blocks {
        let mut at = b.start;
        for (start, len) in &b.insns {
            if *start != at {
                out.push(CfgViolation::Gap { block: b.start });
                break;
            }
            at = start.saturating_add(u64::from(*len));
        }
        if last_end.is_some_and(|e| b.start < e) {
            out.push(CfgViolation::Overlap { block: b.start });
        }
        last_end = Some(b.end());
    }
    let starts: BTreeSet<u64> = cfg.blocks.iter().map(|b| b.start).collect();
    let mut succ: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for e in &cfg.edges {
        let Some(to) = e.to.filter(|_| e.kind.is_internal()) else {
            continue;
        };
        if !starts.contains(&to.off) {
            out.push(CfgViolation::EdgeTarget {
                from: e.from,
                to: to.off,
            });
            continue;
        }
        succ.entry(e.from).or_default().push(to.off);
    }
    let mut seen = BTreeSet::from([entry]);
    let mut todo = vec![entry];
    while let Some(b) = todo.pop() {
        for t in succ.get(&b).into_iter().flatten() {
            if seen.insert(*t) {
                todo.push(*t);
            }
        }
    }
    for b in &cfg.blocks {
        if !seen.contains(&b.start) {
            out.push(CfgViolation::Unreachable { block: b.start });
        }
    }
    out
}
