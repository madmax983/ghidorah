//! The pass `sccp`: constant propagation along the edges that can run (Wegman and Zadeck).
//!
//! Each value has a lattice cell: unknown (top), one constant, or many values (bottom). Two
//! worklists drive the pass. The flow list holds the CFG edges that become live. The value
//! list holds the ops whose inputs changed. A phi meets only the arguments of its live
//! edges. The pass starts from the function entry edge.
//!
//! The flow ops of the last instruction of a block give its live successors:
//!
//! | Op | Next addresses |
//! |---|---|
//! | `CJump(c, t)` | `t` when `c` can be true. The scan goes on when `c` can be false. |
//! | `Jump(t)`, `JumpInd(t)` | `t`. A target with many values makes each successor live. |
//! | `Ret`, `Unimpl` | none |
//! | Other ops | The scan goes on. At the end it adds the next instruction. |
//!
//! After the worklists, each use of a constant value up to 64 bits reads the constant. A
//! `CJump` with a constant condition becomes `Jump` or `Nop`. The CFG loses each edge that
//! never runs, and each phi loses the argument of that edge. Last, the redundant phis go.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::Fuel;

use crate::graph::Node;
use crate::interp::eval;
use crate::op::{Arg, Op, Opc, Val};
use crate::ssa::{Anchor, Ssa, SsaError, cleanup};

/// A lattice cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lat {
    /// No value yet.
    Top,
    /// One constant.
    Const(u128),
    /// Many values.
    Bottom,
}

/// Gives the meet of two cells.
const fn meet(a: Lat, b: Lat) -> Lat {
    match (a, b) {
        (Lat::Top, x) | (x, Lat::Top) => x,
        (Lat::Const(x), Lat::Const(y)) if x == y => a,
        _ => Lat::Bottom,
    }
}

/// The state of one SCCP run.
struct Sccp<'a> {
    ssa: &'a Ssa,
    lat: Vec<Lat>,
    users: BTreeMap<Val, Vec<u32>>,
    ops: Vec<Vec<u32>>,
    live_block: Vec<bool>,
    live_edge: Vec<Vec<bool>>,
    flow: Vec<Node>,
    work: Vec<u32>,
}

impl<'a> Sccp<'a> {
    fn new(ssa: &'a Ssa) -> Self {
        let blocks = ssa.blocks().len();
        let mut users: BTreeMap<Val, Vec<u32>> = BTreeMap::new();
        let mut ops = vec![Vec::new(); blocks];
        for (block, list) in (0u32..).zip(ops.iter_mut()) {
            if Node(block) == ssa.entry() {
                list.extend_from_slice(ssa.anchored(Anchor::Start));
            }
            ssa.block_ops(Node(block), list);
            for &i in list.iter() {
                let Some(op) = ssa.arena().op(i) else {
                    continue;
                };
                let phi_args = if op.opc == Opc::Phi {
                    ssa.arena().phi_args(op).unwrap_or_default()
                } else {
                    &[]
                };
                for arg in op.a.iter().chain(phi_args) {
                    if let Arg::V(v) = arg {
                        users.entry(*v).or_default().push(i);
                    }
                }
            }
        }
        let live_edge = (0..blocks)
            .filter_map(|b| u32::try_from(b).ok())
            .map(|b| vec![false; ssa.phi_arity(Node(b))])
            .collect();
        Self {
            ssa,
            lat: vec![Lat::Top; ssa.arena().val_count()],
            users,
            ops,
            live_block: vec![false; blocks],
            live_edge,
            flow: Vec::new(),
            work: Vec::new(),
        }
    }

    /// Gives the cell of an argument.
    fn cell(&self, arg: Arg) -> Lat {
        match arg {
            Arg::Nil => Lat::Const(0),
            Arg::K(imm) => Lat::Const(u128::from(imm.get())),
            Arg::V(v) => usize::try_from(v.0)
                .ok()
                .and_then(|i| self.lat.get(i))
                .copied()
                .unwrap_or(Lat::Bottom),
            Arg::L(_) => Lat::Bottom,
        }
    }

    /// Marks the edge slot `slot` of `block` live.
    fn add_edge(&mut self, block: Node, slot: usize) {
        if let Some(flag) = self
            .live_edge
            .get_mut(block.index())
            .and_then(|l| l.get_mut(slot))
            && !*flag
        {
            *flag = true;
            self.flow.push(block);
        }
    }

    /// Gives the new cell of an op with a value.
    fn transfer(&self, op: &Op, block: Node) -> Lat {
        match op.opc {
            Opc::Phi => {
                let live = self.live_edge.get(block.index());
                let args = self.ssa.arena().phi_args(op).unwrap_or_default();
                args.iter()
                    .enumerate()
                    .filter(|(j, _)| live.and_then(|l| l.get(*j)).copied().unwrap_or(false))
                    .fold(Lat::Top, |acc, (_, &a)| meet(acc, self.cell(a)))
            }
            Opc::Get | Opc::Load => Lat::Bottom,
            _ => {
                let cells = op.a.map(|a| self.cell(a));
                if cells.contains(&Lat::Bottom) {
                    return Lat::Bottom;
                }
                let [Lat::Const(x), Lat::Const(y), Lat::Const(z)] = cells else {
                    return Lat::Top;
                };
                eval(op.opc, op.w, op.sub, x, y, z).map_or(Lat::Bottom, Lat::Const)
            }
        }
    }

    /// Evaluates one op of a live block.
    fn visit(&mut self, index: u32, block: Node) {
        let Some(&op) = self.ssa.arena().op(index) else {
            return;
        };
        if let Some(out) = op.out
            && let Some(slot) = usize::try_from(out.0).ok().and_then(|i| self.lat.get(i))
        {
            let old = *slot;
            let new = meet(old, self.transfer(&op, block));
            if new != old {
                if let Some(cell) = usize::try_from(out.0)
                    .ok()
                    .and_then(|i| self.lat.get_mut(i))
                {
                    *cell = new;
                }
                if let Some(list) = self.users.get(&out) {
                    self.work.extend(list.iter().copied());
                }
            }
        }
        if op.opc.is_flow() {
            self.successors(block);
        }
    }

    /// Gives the next addresses of a block, or `None` when each successor can come next.
    fn next_addrs(&self, block: Node) -> Option<BTreeSet<u64>> {
        let mut addrs = BTreeSet::new();
        let span = self.ssa.last_insn(block)?;
        let target = |a: Arg, addrs: &mut BTreeSet<u64>| match self.cell(a) {
            Lat::Const(t) => {
                if let Ok(t) = u64::try_from(t) {
                    addrs.insert(t);
                }
                Some(())
            }
            Lat::Bottom => None,
            Lat::Top => Some(()),
        };
        for i in span.first..span.first.saturating_add(span.count) {
            let Some(op) = self.ssa.arena().op(i) else {
                continue;
            };
            match op.opc {
                Opc::CJump => match self.cell(op.a[0]) {
                    Lat::Top => return Some(addrs),
                    Lat::Const(0) => {}
                    Lat::Const(_) => {
                        target(op.a[1], &mut addrs)?;
                        return Some(addrs);
                    }
                    Lat::Bottom => target(op.a[1], &mut addrs)?,
                },
                Opc::Jump | Opc::JumpInd => {
                    target(op.a[0], &mut addrs)?;
                    return Some(addrs);
                }
                Opc::Ret | Opc::Unimpl => return Some(addrs),
                _ => {}
            }
        }
        if let Some(next) = span.next_addr() {
            addrs.insert(next);
        }
        Some(addrs)
    }

    /// Marks the live out-edges of a live block.
    fn successors(&mut self, block: Node) {
        let addrs = self.next_addrs(block);
        let succs: BTreeSet<Node> = self.ssa.cfg().succs(block).iter().copied().collect();
        for succ in succs {
            let wanted = match &addrs {
                None => true,
                Some(set) => self.ssa.block_addr(succ).is_some_and(|a| set.contains(&a)),
            };
            if !wanted {
                continue;
            }
            let slots: Vec<usize> = self
                .ssa
                .preds(succ)
                .iter()
                .enumerate()
                .filter(|&(_, &p)| p == block)
                .map(|(j, _)| j)
                .collect();
            for slot in slots {
                self.add_edge(succ, slot);
            }
        }
    }

    /// Runs the two worklists until both are empty.
    fn solve(&mut self, fuel: &mut Fuel) -> Result<(), SsaError> {
        let entry = self.ssa.entry();
        self.add_edge(entry, self.ssa.preds(entry).len());
        loop {
            if let Some(block) = self.flow.pop() {
                fuel.tick()?;
                let first = !self.live_block.get(block.index()).copied().unwrap_or(true);
                if let Some(flag) = self.live_block.get_mut(block.index()) {
                    *flag = true;
                }
                let list = self.ops.get(block.index()).cloned().unwrap_or_default();
                for index in list {
                    let is_phi = self
                        .ssa
                        .arena()
                        .op(index)
                        .is_some_and(|op| op.opc == Opc::Phi);
                    if first || is_phi {
                        fuel.tick()?;
                        self.visit(index, block);
                    }
                }
                if first {
                    self.successors(block);
                }
            } else if let Some(index) = self.work.pop() {
                fuel.tick()?;
                if let Some(block) = self.ssa.block_of_op(index)
                    && self.live_block.get(block.index()).copied().unwrap_or(false)
                {
                    self.visit(index, block);
                }
            } else {
                return Ok(());
            }
        }
    }

    /// Tells if the edge `from -> to` can run.
    fn edge_live(&self, from: Node, to: Node) -> bool {
        let live = self.live_edge.get(to.index());
        self.ssa
            .preds(to)
            .iter()
            .enumerate()
            .any(|(j, &p)| p == from && live.and_then(|l| l.get(j)).copied().unwrap_or(false))
    }
}

/// Runs `sccp`. Gives the count of changes: constant uses, rewritten jumps, removed edges
/// and removed phis.
///
/// # Errors
///
/// Returns [`SsaError::OutOfFuel`] when the plan runs out of fuel. Then the pass makes no
/// change.
pub(crate) fn run(ssa: &mut Ssa, fuel: &mut Fuel) -> Result<u64, SsaError> {
    let mut state = Sccp::new(ssa);
    state.solve(fuel)?;
    let mut repl = BTreeMap::new();
    for (i, cell) in (0u32..).zip(&state.lat) {
        if let Lat::Const(c) = *cell
            && let Ok(c) = u64::try_from(c)
        {
            repl.insert(Val(i), Arg::k(c));
        }
    }
    let count = ssa.cfg().len();
    let keep: BTreeSet<(Node, Node)> = (0..count)
        .filter_map(|i| u32::try_from(i).ok().map(Node))
        .flat_map(|from| ssa.cfg().succs(from).iter().map(move |&to| (from, to)))
        .filter(|&(from, to)| state.edge_live(from, to))
        .collect();
    let mut changes = ssa.replace_uses(&repl);
    let order: Vec<u32> = ssa
        .order()
        .into_iter()
        .filter(|&i| ssa.is_insn_op(i))
        .collect();
    for index in order {
        let Some(&op) = ssa.arena().op(index) else {
            continue;
        };
        if let (Opc::CJump, Some(c)) = (op.opc, op.a[0].as_k()) {
            if c == 0 {
                ssa.remove_op(index);
            } else {
                ssa.set_op(index, Opc::Jump, 64, 0, [op.a[1], Arg::Nil, Arg::Nil]);
            }
            changes = changes.saturating_add(1);
        }
    }
    let removed = ssa.retain_edges(&|from, to| keep.contains(&(from, to)));
    changes = changes.saturating_add(removed);
    if removed > 0 {
        let phis = cleanup::all_phis(ssa);
        let phi_repl = cleanup::redundant_phis(ssa, &phis, &mut Fuel::unlimited())?;
        changes = changes.saturating_add(cleanup::apply(ssa, &phis, &phi_repl));
    }
    Ok(changes)
}
