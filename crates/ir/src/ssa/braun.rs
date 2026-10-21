//! The value of a location at a block start: Braun SSA with all blocks sealed.
//!
//! The CFG does not change, so the build seals all blocks at the start. The local step
//! gives the last write of each location in each block.
//!
//! A read at a block start walks up the chain of single predecessors in a loop. The walk
//! stops at a block with a write, at a known value, at the function start or at a merge
//! block. A merge block gets an empty phi at once. The walk keeps its result for each block
//! of the chain. The phi gets its arguments later, from a list of open phis. So no read
//! recurses.
//!
//! A chain of single predecessors that goes back to itself has no entry, so no run reaches
//! it. The walk puts a phi in such a cycle, and the cleanup keeps that phi.

use std::collections::BTreeMap;

use ghidorah_base::Fuel;

use crate::graph::Node;
use crate::loc::Loc;
use crate::op::{Arg, Opc};

use super::{Anchor, Ssa, SsaError};

/// The state of the reads of one build.
pub(super) struct Reader {
    /// The last write of each location in each block.
    local: Vec<BTreeMap<Loc, Arg>>,
    /// The known value of a location at the start of a block.
    memo: BTreeMap<(u32, Loc), Arg>,
    /// The entry value of each location: a `Get` at the anchor `Start`.
    entry: BTreeMap<Loc, Arg>,
    /// The phis without arguments: the block, the location and the phi op.
    open: Vec<(Node, Loc, u32)>,
    /// The walk that last visited each block.
    stamp: Vec<u32>,
    /// The number of the current walk.
    walk: u32,
    /// Every phi of the build.
    pub(super) phis: Vec<u32>,
}

impl Reader {
    /// Makes the reader of a body with `blocks` blocks.
    pub(super) fn new(blocks: usize) -> Self {
        Self {
            local: vec![BTreeMap::new(); blocks],
            memo: BTreeMap::new(),
            entry: BTreeMap::new(),
            open: Vec::new(),
            stamp: vec![0; blocks],
            walk: 0,
            phis: Vec::new(),
        }
    }

    /// Sets the last writes of a block.
    pub(super) fn set_local(&mut self, block: Node, defs: BTreeMap<Loc, Arg>) {
        if let Some(slot) = self.local.get_mut(block.index()) {
            *slot = defs;
        }
    }

    /// Gives the entry value of `loc`. The first call adds its `Get` at the anchor `Start`.
    fn entry_value(&mut self, ssa: &mut Ssa, loc: Loc) -> Result<Arg, SsaError> {
        if let Some(&v) = self.entry.get(&loc) {
            return Ok(v);
        }
        let a = [Arg::L(loc), Arg::Nil, Arg::Nil];
        let (_, out) = ssa.push_at(Anchor::Start, Opc::Get, loc.width(), 0, a)?;
        let v = Arg::V(out.ok_or(SsaError::Full)?);
        self.entry.insert(loc, v);
        Ok(v)
    }

    /// Gives the value of `loc` at the end of `block`.
    fn read_end(
        &mut self,
        ssa: &mut Ssa,
        block: Node,
        loc: Loc,
        fuel: &mut Fuel,
    ) -> Result<Arg, SsaError> {
        if let Some(&v) = self.local.get(block.index()).and_then(|m| m.get(&loc)) {
            return Ok(v);
        }
        self.read_start(ssa, block, loc, fuel)
    }

    /// Gives the value of `loc` at the start of `block`. Each step takes one unit of fuel.
    pub(super) fn read_start(
        &mut self,
        ssa: &mut Ssa,
        block: Node,
        loc: Loc,
        fuel: &mut Fuel,
    ) -> Result<Arg, SsaError> {
        self.walk = self.walk.wrapping_add(1);
        if self.walk == 0 {
            self.stamp.fill(0);
            self.walk = 1;
        }
        let entry = ssa.entry();
        let mut path = Vec::new();
        let mut x = block;
        let result = loop {
            fuel.tick()?;
            if let Some(&v) = self.memo.get(&(x.0, loc)) {
                break v;
            }
            let (count, first) = {
                let preds = ssa.preds(x);
                (preds.len(), preds.first().copied())
            };
            let cycle = self.stamp.get(x.index()) == Some(&self.walk);
            let Some(pred) = first else {
                break self.entry_value(ssa, loc)?;
            };
            if x == entry || count > 1 || cycle {
                let (phi, val) = ssa.push_phi(x, loc.width(), Vec::new())?;
                ssa.phi_locs.insert(phi, loc);
                self.memo.insert((x.0, loc), Arg::V(val));
                self.open.push((x, loc, phi));
                self.phis.push(phi);
                break Arg::V(val);
            }
            if let Some(slot) = self.stamp.get_mut(x.index()) {
                *slot = self.walk;
            }
            path.push(x);
            if let Some(&v) = self.local.get(pred.index()).and_then(|m| m.get(&loc)) {
                break v;
            }
            x = pred;
        };
        for y in path {
            self.memo.insert((y.0, loc), result);
        }
        Ok(result)
    }

    /// Gives each open phi its arguments: one for each predecessor, plus the entry value in
    /// the entry block.
    pub(super) fn finish(&mut self, ssa: &mut Ssa, fuel: &mut Fuel) -> Result<(), SsaError> {
        while let Some((block, loc, phi)) = self.open.pop() {
            let preds = ssa.preds(block).to_vec();
            let mut args = Vec::with_capacity(preds.len().saturating_add(1));
            for pred in preds {
                args.push(self.read_end(ssa, pred, loc, fuel)?);
            }
            if block == ssa.entry() {
                args.push(self.entry_value(ssa, loc)?);
            }
            ssa.set_phi_args(phi, args);
        }
        Ok(())
    }
}
