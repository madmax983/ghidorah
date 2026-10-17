//! L1 in the interpreter (design Sections 6.4 and 6.5).
//!
//! [`Interp::run_l1`] runs an [`Ssa`] with the one interpreter of L0. The instruction ops run
//! as in L0, and each takes one unit of fuel. So L0 and L1 take the same steps.
//!
//! The added ops of L1 take no fuel. They run at their anchor:
//!
//! | Anchor | When the ops run |
//! |---|---|
//! | `Start` | Once, before the entry block |
//! | `Head(b)` | At each entry to `b`. The phis read the argument of the incoming edge, all at the same time. |
//! | `Before(i)`, `After(i)` | Before and after the instruction op `i` |
//! | `Tail(b)` | At each exit from `b` to a successor, before the phis of the successor |
//!
//! An L1 run never writes a location, so a `Get` op reads the location state at the start
//! of the run. A flow that goes to an address outside the CFG edges stops the run with
//! [`StopReason::BadIr`].

use ghidorah_base::Fuel;

use super::{Flow, Interp, Stop, StopReason, mask, stop};
use crate::graph::Node;
use crate::op::{Op, OpId, Opc};
use crate::ssa::{Anchor, Ssa};

impl Interp<'_> {
    /// Runs the L1 form `ssa` from its entry block until a stop.
    ///
    /// Make the interpreter over the arena of `ssa`. A run over another arena stops at once
    /// with [`StopReason::BadIr`].
    pub fn run_l1(&mut self, ssa: &Ssa, fuel: &mut Fuel) -> Stop {
        let entry = ssa.entry();
        let start = ssa.block_addr(entry).unwrap_or_default();
        let mut at = OpId {
            addr: start,
            seq: 0,
        };
        if !std::ptr::eq(self.arena, ssa.arena()) {
            return stop(StopReason::BadIr, at, 0);
        }
        let mut steps = 0u64;
        let begin = self
            .run_added(ssa.anchored(Anchor::Start), &mut at)
            .and_then(|()| self.enter(ssa, entry, ssa.preds(entry).len(), &mut at));
        if let Err(reason) = begin {
            return stop(reason, at, steps);
        }
        let mut cur = entry;
        let mut target = start;
        loop {
            let Some(index) = self.arena.insn_index(target) else {
                return stop(StopReason::NoCode(target), at, steps);
            };
            let Some(span) = self.arena.insns().get(index).copied() else {
                return stop(StopReason::NoCode(target), at, steps);
            };
            let ops = self.arena.span_ops(&span).unwrap_or_default();
            if ops.is_empty() {
                at = OpId {
                    addr: span.addr,
                    seq: 0,
                };
                if fuel.tick().is_err() {
                    return stop(StopReason::FuelExhausted, at, steps);
                }
                steps = steps.saturating_add(1);
            }
            let mut jump = None;
            for (op, i) in ops.iter().zip(span.first..) {
                at = op.id;
                if fuel.tick().is_err() {
                    return stop(StopReason::FuelExhausted, at, steps);
                }
                steps = steps.saturating_add(1);
                if let Err(reason) = self.run_added(ssa.anchored(Anchor::Before(i)), &mut at) {
                    return stop(reason, at, steps);
                }
                at = op.id;
                match self.step(op) {
                    Flow::Next => {
                        if let Err(reason) = self.run_added(ssa.anchored(Anchor::After(i)), &mut at)
                        {
                            return stop(reason, at, steps);
                        }
                    }
                    Flow::Goto(addr) => {
                        jump = Some(addr);
                        break;
                    }
                    Flow::Stop(reason) => return stop(reason, at, steps),
                }
            }
            let Some(next) = jump.or_else(|| span.next_addr()) else {
                return stop(StopReason::NoCode(0), at, steps);
            };
            if let Some(block) = ssa.block_at(next) {
                let moved = self.leave(ssa, cur, block, &mut at);
                if let Err(reason) = moved {
                    return stop(reason, at, steps);
                }
                cur = block;
            } else {
                match self.arena.insn_index(next) {
                    None => return stop(StopReason::NoCode(next), at, steps),
                    Some(ni)
                        if ni == index.saturating_add(1) && ssa.block_of_insn(ni) == Some(cur) => {}
                    Some(_) => return stop(StopReason::BadIr, at, steps),
                }
            }
            target = next;
        }
    }

    /// Runs the tail of `from` and enters `to` over the edge `from -> to`.
    fn leave(&mut self, ssa: &Ssa, from: Node, to: Node, at: &mut OpId) -> Result<(), StopReason> {
        self.run_added(ssa.anchored(Anchor::Tail(from)), at)?;
        let slot = ssa
            .preds(to)
            .iter()
            .position(|&p| p == from)
            .ok_or(StopReason::BadIr)?;
        self.enter(ssa, to, slot, at)
    }

    /// Runs the added ops of one anchor in order.
    fn run_added(&mut self, list: &[u32], at: &mut OpId) -> Result<(), StopReason> {
        for &index in list {
            let op = *self.arena.op(index).ok_or(StopReason::BadIr)?;
            *at = op.id;
            match self.step(&op) {
                Flow::Next => {}
                Flow::Goto(_) => return Err(StopReason::BadIr),
                Flow::Stop(reason) => return Err(reason),
            }
        }
        Ok(())
    }

    /// Enters `block` over the incoming edge `slot`: the phis read their argument `slot`, all
    /// at the same time.
    fn enter(
        &mut self,
        ssa: &Ssa,
        block: Node,
        slot: usize,
        at: &mut OpId,
    ) -> Result<(), StopReason> {
        let phis = ssa.anchored(Anchor::Head(block));
        let mut values: Vec<(Op, u128)> = Vec::with_capacity(phis.len());
        for &index in phis {
            let op = *self.arena.op(index).ok_or(StopReason::BadIr)?;
            *at = op.id;
            if op.opc != Opc::Phi {
                return Err(StopReason::BadIr);
            }
            let arg = self
                .arena
                .phi_args(&op)
                .and_then(|args| args.get(slot).copied())
                .ok_or(StopReason::BadIr)?;
            let value = self.arg(arg).ok_or(StopReason::BadIr)?;
            values.push((op, value & mask(op.w)));
        }
        for (op, value) in values {
            *at = op.id;
            if let Flow::Stop(reason) = self.def(&op, value) {
                return Err(reason);
            }
        }
        Ok(())
    }
}
