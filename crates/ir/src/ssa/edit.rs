//! Edits of an [`Ssa`]: added ops, op rewrites, removed ops, value replacement and CFG edges.

use std::collections::BTreeMap;

use crate::graph::{Cfg, Node};
use crate::op::{Arg, Op, OpId, Opc, Val};

use super::{Anchor, PASS_SEQ, PHI_SEQ, Ssa, SsaError};

/// The count of phi sequence numbers of one address.
const PHI_SEQS: u16 = u16::MAX - PHI_SEQ + 1;

/// The count of pass sequence numbers of one address.
const PASS_SEQS: u16 = PHI_SEQ - PASS_SEQ;

/// Follows the replacement chain of `arg` in `repl`. The walk stops after `repl.len()` steps.
pub(crate) fn find(repl: &BTreeMap<Val, Arg>, arg: Arg) -> Arg {
    let mut cur = arg;
    for _ in 0..=repl.len() {
        match cur {
            Arg::V(v) => match repl.get(&v) {
                Some(&next) if next != cur => cur = next,
                _ => return cur,
            },
            _ => return cur,
        }
    }
    cur
}

impl Ssa {
    /// Gives the next sequence number of `addr` for a phi or for another added op.
    fn next_seq(&mut self, addr: u64, phi: bool) -> Result<u16, SsaError> {
        let slot = self.seqs.entry(addr).or_insert([0, 0]);
        let (count, base, limit) = if phi {
            (&mut slot[1], PHI_SEQ, PHI_SEQS)
        } else {
            (&mut slot[0], PASS_SEQ, PASS_SEQS)
        };
        if *count >= limit {
            return Err(SsaError::SeqFull { addr });
        }
        let seq = base.saturating_add(*count);
        *count = count.saturating_add(1);
        Ok(seq)
    }

    /// Gives the address of an anchor: the address of its block or of its op.
    fn anchor_addr(&self, anchor: Anchor) -> u64 {
        let addr = match anchor {
            Anchor::Start => self.block_addr(self.entry()),
            Anchor::Head(b) => self.block_addr(b),
            Anchor::Tail(b) => self.last_insn(b).map(|s| s.addr),
            Anchor::Before(i) | Anchor::After(i) => self.arena.op(i).map(|op| op.id.addr),
        };
        addr.unwrap_or_default()
    }

    /// Adds an op to the anchor list at `pos`, or at the end. Gives its index and its value.
    fn push_into(
        &mut self,
        anchor: Anchor,
        pos: Option<usize>,
        opc: Opc,
        w: u8,
        sub: u8,
        a: [Arg; 3],
    ) -> Result<(u32, Option<Val>), SsaError> {
        let addr = self.anchor_addr(anchor);
        let seq = self.next_seq(addr, opc == Opc::Phi)?;
        let op = Op {
            id: OpId { addr, seq },
            opc,
            w,
            sub,
            out: None,
            a,
        };
        let (index, out) = self.arena.push_op(op)?;
        let list = self.anchors.entry(anchor).or_default();
        match pos {
            Some(p) if p <= list.len() => list.insert(p, index),
            _ => list.push(index),
        }
        self.places.insert(index, anchor);
        Ok((index, out))
    }

    /// Adds an op at the end of `anchor`. Gives its index and its value.
    pub(crate) fn push_at(
        &mut self,
        anchor: Anchor,
        opc: Opc,
        w: u8,
        sub: u8,
        a: [Arg; 3],
    ) -> Result<(u32, Option<Val>), SsaError> {
        self.push_into(anchor, None, opc, w, sub, a)
    }

    /// Adds an op that has a value just before the op `index`. Gives the value.
    pub(crate) fn push_before(
        &mut self,
        index: u32,
        opc: Opc,
        w: u8,
        a: [Arg; 3],
    ) -> Result<Val, SsaError> {
        let (anchor, pos) = match self.place(index) {
            Some(anchor) => {
                let pos = self.anchored(anchor).iter().position(|&i| i == index);
                (anchor, pos)
            }
            None => (Anchor::Before(index), None),
        };
        let (_, out) = self.push_into(anchor, pos, opc, w, 0, a)?;
        out.ok_or(SsaError::Full)
    }

    /// Adds a phi of `w` bits with `args` at the head of `block`. Gives its index and value.
    pub(crate) fn push_phi(
        &mut self,
        block: Node,
        w: u8,
        args: Vec<Arg>,
    ) -> Result<(u32, Val), SsaError> {
        let list = self.arena.push_phi_args(args)?;
        let a = [Arg::k(u64::from(list)), Arg::Nil, Arg::Nil];
        let (index, out) = self.push_at(Anchor::Head(block), Opc::Phi, w, 0, a)?;
        Ok((index, out.ok_or(SsaError::Full)?))
    }

    /// Gives the index of the argument list of the phi op `index`.
    pub(crate) fn phi_list(&self, index: u32) -> Option<u32> {
        let op = self.arena.op(index)?;
        if op.opc != Opc::Phi {
            return None;
        }
        u32::try_from(op.a[0].as_k()?).ok()
    }

    /// Gives the arguments of the phi op `index`.
    pub(crate) fn phi_args_of(&self, index: u32) -> &[Arg] {
        self.arena
            .op(index)
            .and_then(|op| self.arena.phi_args(op))
            .unwrap_or_default()
    }

    /// Sets the arguments of the phi op `index`.
    pub(crate) fn set_phi_args(&mut self, index: u32, args: Vec<Arg>) {
        if let Some(slot) = self
            .phi_list(index)
            .and_then(|list| self.arena.phi_args_mut(list))
        {
            *slot = args;
        }
    }

    /// Rewrites the op `index` in place. It keeps its ID, and it keeps its value when the
    /// new opcode has one.
    pub(crate) fn set_op(&mut self, index: u32, opc: Opc, w: u8, sub: u8, a: [Arg; 3]) {
        let Some(op) = usize::try_from(index)
            .ok()
            .and_then(|i| self.arena.ops_mut().get_mut(i))
        else {
            return;
        };
        op.opc = opc;
        op.w = w;
        op.sub = sub;
        op.a = a;
        if !opc.has_out() {
            op.out = None;
        }
    }

    /// Removes an op: it becomes a `Nop` with no value, and an added op leaves its anchor.
    pub(crate) fn remove_op(&mut self, index: u32) {
        self.set_op(index, Opc::Nop, 0, 0, [Arg::Nil; 3]);
        if let Some(anchor) = self.places.remove(&index)
            && let Some(list) = self.anchors.get_mut(&anchor)
        {
            list.retain(|&i| i != index);
            if list.is_empty() {
                self.anchors.remove(&anchor);
            }
        }
    }

    /// Replaces each use of a value of `repl` with its value, through chains. Gives the count
    /// of changed arguments.
    ///
    /// The uses are the arguments of the L1 ops, the phi arguments and the location uses.
    pub(crate) fn replace_uses(&mut self, repl: &BTreeMap<Val, Arg>) -> u64 {
        if repl.is_empty() {
            return 0;
        }
        let mut changes = 0u64;
        let mut swap = |arg: &mut Arg| {
            if let Arg::V(v) = *arg
                && repl.contains_key(&v)
            {
                let new = find(repl, *arg);
                if new != *arg {
                    *arg = new;
                    changes = changes.saturating_add(1);
                }
            }
        };
        for index in self.order() {
            let list = self.phi_list(index);
            if let Some(op) = usize::try_from(index)
                .ok()
                .and_then(|i| self.arena.ops_mut().get_mut(i))
                && op.opc != Opc::Phi
            {
                op.a.iter_mut().for_each(&mut swap);
            }
            if let Some(args) = list.and_then(|l| self.arena.phi_args_mut(l)) {
                args.iter_mut().for_each(&mut swap);
            }
        }
        for list in self.uses.values_mut() {
            for (_, arg) in list.iter_mut() {
                swap(arg);
            }
        }
        changes
    }

    /// Keeps the CFG edges for which `keep` is true, and removes the phi arguments of the
    /// other edges. Gives the count of removed edges.
    pub(crate) fn retain_edges(&mut self, keep: &dyn Fn(Node, Node) -> bool) -> u64 {
        let count = self.cfg.len();
        let Ok(mut cfg) = Cfg::new(count, self.cfg.entry()) else {
            return 0;
        };
        let mut removed = 0u64;
        for from in (0..count).filter_map(|i| u32::try_from(i).ok().map(Node)) {
            for &to in self.cfg.succs(from) {
                if keep(from, to) {
                    // Both nodes come from the old graph, so the edge is valid.
                    let _valid = cfg.add_edge(from, to);
                } else {
                    removed = removed.saturating_add(1);
                }
            }
        }
        if removed == 0 {
            return 0;
        }
        let entry = self.entry();
        for block in (0..count).filter_map(|i| u32::try_from(i).ok().map(Node)) {
            let preds = self.preds(block).to_vec();
            for phi in self.phis(block).to_vec() {
                let args = self.phi_args_of(phi);
                let kept: Vec<Arg> = args
                    .iter()
                    .enumerate()
                    .filter(|&(j, _)| preds.get(j).map_or(block == entry, |&p| keep(p, block)))
                    .map(|(_, &a)| a)
                    .collect();
                self.set_phi_args(phi, kept);
            }
        }
        self.preds = cfg.preds();
        self.cfg = cfg;
        removed
    }
}
