//! The SSA build: the body check, the local step over each block, the reads at block starts
//! and the phi cleanup.

use std::collections::BTreeMap;

use ghidorah_base::Fuel;

use crate::arena::{Arena, MAX_WIDTH};
use crate::graph::Node;
use crate::loc::{Loc, LocSet};
use crate::op::{Arg, Op, Opc};

use super::braun::Reader;
use super::cleanup;
use super::{Anchor, Body, NO_BLOCK, Opts, Ssa, SsaError, low_mask};

/// A read of a location at a block start, from the local step.
#[derive(Debug, Clone, Copy)]
enum Read {
    /// The `Get` op `op` becomes `Copy` of the value.
    Get {
        /// The op.
        op: u32,
        /// The block of the op.
        block: Node,
        /// The location.
        loc: Loc,
    },
    /// The location use `slot` of the flow op `op` takes the value.
    Use {
        /// The op.
        op: u32,
        /// The index in the use list of the op.
        slot: usize,
        /// The block of the op.
        block: Node,
        /// The location.
        loc: Loc,
    },
}

/// Gives the block of each instruction and of each instruction op.
fn layout(arena: &Arena, body: &Body) -> Result<(Vec<u32>, Vec<u32>), SsaError> {
    let blocks = body.blocks.len();
    if body.cfg.len() != blocks {
        return Err(SsaError::BlockCount {
            blocks,
            nodes: body.cfg.len(),
        });
    }
    let insns = arena.insns();
    let mut insn_block = vec![NO_BLOCK; insns.len()];
    for (block, b) in (0u32..).zip(&body.blocks) {
        let bad = SsaError::BadBlock { block: Node(block) };
        let first = usize::try_from(b.first).map_err(|_| bad)?;
        let count = usize::try_from(b.count).map_err(|_| bad)?;
        let end = first.checked_add(count).ok_or(bad)?;
        if count == 0 || end > insns.len() {
            return Err(bad);
        }
        for (slot, span) in insn_block.iter_mut().zip(insns).skip(first).take(count) {
            if *slot != NO_BLOCK {
                return Err(SsaError::InsnCover { addr: span.addr });
            }
            *slot = block;
        }
    }
    if let Some((_, span)) = insn_block.iter().zip(insns).find(|(b, _)| **b == NO_BLOCK) {
        return Err(SsaError::InsnCover { addr: span.addr });
    }
    let mut op_block = vec![NO_BLOCK; arena.ops().len()];
    for (span, &block) in insns.iter().zip(&insn_block) {
        let first = usize::try_from(span.first).unwrap_or(usize::MAX);
        let count = usize::try_from(span.count).unwrap_or(0);
        for slot in op_block.iter_mut().skip(first).take(count) {
            *slot = block;
        }
    }
    Ok((insn_block, op_block))
}

/// Gives the location uses and defs of a flow op, or `None` for another op.
fn flow_sets(arena: &Arena, op: &Op, opts: &Opts) -> Result<(LocSet, LocSet), SsaError> {
    match op.opc {
        Opc::Ret => Ok((opts.ret_uses, LocSet::EMPTY)),
        Opc::Call | Opc::CallInd => Ok((opts.call_uses, opts.call_defs)),
        Opc::Syscall | Opc::Intrinsic => arena
            .effect(op)
            .map(|e| (e.uses, e.defs))
            .ok_or(SsaError::BadOp { at: op.id }),
        _ => Ok((LocSet::EMPTY, LocSet::EMPTY)),
    }
}

/// Tells if `w` is a valid width of a location op.
const fn loc_width(w: u8) -> bool {
    w != 0 && w <= MAX_WIDTH
}

/// The local step over one block.
struct Local<'a> {
    ssa: &'a mut Ssa,
    opts: &'a Opts,
    calls: &'a BTreeMap<u32, Vec<Loc>>,
    reads: &'a mut Vec<Read>,
    block: Node,
    defs: BTreeMap<Loc, Arg>,
}

impl Local<'_> {
    /// Gives the value that `Put(loc, value)` of `m` bits leaves in the location.
    fn narrow(&mut self, index: u32, value: Arg, m: u8) -> Result<Arg, SsaError> {
        if m == 0 {
            return Ok(Arg::k(0));
        }
        match value {
            Arg::K(imm) => Ok(Arg::k(imm.get() & low_mask(m))),
            Arg::V(x) if self.ssa.value_width(x).is_some_and(|w| w <= m) => Ok(value),
            _ => {
                let a = [value, Arg::Nil, Arg::Nil];
                let (_, out) = self
                    .ssa
                    .push_at(Anchor::After(index), Opc::Trunc, m, 0, a)?;
                Ok(Arg::V(out.ok_or(SsaError::Full)?))
            }
        }
    }

    /// Records the location uses and adds the location defs of a flow op.
    fn flow(&mut self, index: u32, op: &Op) -> Result<(), SsaError> {
        let (set, defs) = flow_sets(&self.ssa.arena, op, self.opts)?;
        let uses: Vec<Loc> = match self.calls.get(&index) {
            Some(own) if matches!(op.opc, Opc::Call | Opc::CallInd) => {
                let mut own = own.clone();
                own.sort_unstable();
                own.dedup();
                own
            }
            _ => set.iter().collect(),
        };
        let mut list = Vec::new();
        for loc in uses {
            let value = self.defs.get(&loc).copied().unwrap_or_else(|| {
                self.reads.push(Read::Use {
                    op: index,
                    slot: list.len(),
                    block: self.block,
                    loc,
                });
                Arg::Nil
            });
            list.push((loc, value));
        }
        if !list.is_empty() {
            self.ssa.uses.insert(index, list);
        }
        let mut made = Vec::new();
        for loc in defs.iter() {
            let a = [Arg::L(loc), Arg::Nil, Arg::Nil];
            let (_, out) = self
                .ssa
                .push_at(Anchor::After(index), Opc::Get, loc.width(), 0, a)?;
            let v = out.ok_or(SsaError::Full)?;
            self.defs.insert(loc, Arg::V(v));
            made.push((loc, v));
        }
        if !made.is_empty() {
            self.ssa.defs.insert(index, made);
        }
        if matches!(op.opc, Opc::Call | Opc::CallInd)
            && let Some((loc, count)) = self.opts.call_pop
            && !defs.contains(loc)
            && let Some(&before) = self.defs.get(&loc)
        {
            let after = self.popped(index, before, loc, count)?;
            self.defs.insert(loc, after);
        }
        Ok(())
    }

    /// Gives the value of `loc` after the callee of the call op `index` pops `count` bytes.
    /// The value before the call is `before`. When `before` is `x - count`, the push of the
    /// call, the value is `x`. Else a new `Add` after the call gives `before + count`.
    fn popped(&mut self, index: u32, before: Arg, loc: Loc, count: u64) -> Result<Arg, SsaError> {
        let w = loc.width();
        if let Arg::V(v) = before
            && let Some(push) = self.ssa.arena.def_of(v).and_then(|d| self.ssa.arena.op(d))
            && push.opc == Opc::Sub
            && push.w == w
            && push.a[1].as_k() == Some(count)
            && matches!(push.a[0], Arg::V(_))
        {
            return Ok(push.a[0]);
        }
        let a = [before, Arg::k(count), Arg::Nil];
        let (_, out) = self.ssa.push_at(Anchor::After(index), Opc::Add, w, 0, a)?;
        Ok(Arg::V(out.ok_or(SsaError::Full)?))
    }

    /// Runs the local step over the ops of the block.
    fn run(&mut self, fuel: &mut Fuel) -> Result<(), SsaError> {
        for index in self.ssa.insn_op_range(self.block) {
            fuel.tick()?;
            let op = *self.ssa.arena.op(index).ok_or(SsaError::Full)?;
            let bad = SsaError::BadOp { at: op.id };
            match op.opc {
                Opc::Get => {
                    let loc = op.a[0].as_loc().ok_or(bad)?;
                    if !loc_width(op.w) {
                        return Err(bad);
                    }
                    if let Some(&v) = self.defs.get(&loc) {
                        self.ssa
                            .set_op(index, Opc::Copy, op.w, 0, [v, Arg::Nil, Arg::Nil]);
                    } else {
                        self.reads.push(Read::Get {
                            op: index,
                            block: self.block,
                            loc,
                        });
                    }
                }
                Opc::Put => {
                    let loc = op.a[0].as_loc().ok_or(bad)?;
                    if !loc_width(op.w) || !matches!(op.a[1], Arg::V(_) | Arg::K(_)) {
                        return Err(bad);
                    }
                    let value = self.narrow(index, op.a[1], op.w.min(loc.width()))?;
                    self.defs.insert(loc, value);
                    self.ssa.set_op(index, Opc::Nop, 0, 0, [Arg::Nil; 3]);
                }
                Opc::Phi => return Err(bad),
                _ if op.a.iter().any(|a| matches!(a, Arg::L(_))) => return Err(bad),
                _ => self.flow(index, &op)?,
            }
        }
        Ok(())
    }
}

/// Makes the L1 form of `arena` over `body` (see [`super::build`]).
pub(super) fn build(
    arena: Arena,
    body: Body,
    opts: &Opts,
    calls: &BTreeMap<u32, Vec<Loc>>,
    fuel: &mut Fuel,
) -> Result<Ssa, SsaError> {
    let (insn_block, op_block) = layout(&arena, &body)?;
    let preds = body.cfg.preds();
    let mut ssa = Ssa {
        arena,
        blocks: body.blocks,
        cfg: body.cfg,
        preds,
        insn_block,
        op_block,
        anchors: BTreeMap::new(),
        places: BTreeMap::new(),
        uses: BTreeMap::new(),
        defs: BTreeMap::new(),
        seqs: BTreeMap::new(),
        phi_locs: BTreeMap::new(),
        fused: BTreeMap::new(),
    };
    let count = ssa.blocks.len();
    let mut reader = Reader::new(count);
    let mut reads = Vec::new();
    for block in (0..count).filter_map(|i| u32::try_from(i).ok().map(Node)) {
        let mut local = Local {
            ssa: &mut ssa,
            opts,
            calls,
            reads: &mut reads,
            block,
            defs: BTreeMap::new(),
        };
        local.run(fuel)?;
        let defs = local.defs;
        reader.set_local(block, defs);
    }
    let mut values = Vec::with_capacity(reads.len());
    for read in &reads {
        let (Read::Get { block, loc, .. } | Read::Use { block, loc, .. }) = *read;
        values.push(reader.read_start(&mut ssa, block, loc, fuel)?);
    }
    reader.finish(&mut ssa, fuel)?;
    for (read, value) in reads.iter().zip(values) {
        match *read {
            Read::Get { op, .. } => {
                let w = ssa.arena.op(op).map_or(0, |o| o.w);
                ssa.set_op(op, Opc::Copy, w, 0, [value, Arg::Nil, Arg::Nil]);
            }
            Read::Use { op, slot, .. } => {
                if let Some(entry) = ssa.uses.get_mut(&op).and_then(|l| l.get_mut(slot)) {
                    entry.1 = value;
                }
            }
        }
    }
    let repl = cleanup::redundant_phis(&ssa, &reader.phis, fuel)?;
    cleanup::apply(&mut ssa, &reader.phis, &repl);
    Ok(ssa)
}
