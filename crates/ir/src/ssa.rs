//! L1: Braun SSA over an L0 arena and its CFG (design Section 6.4, ADR-0009).
//!
//! [`build`] takes an L0 [`Arena`] and its [`Body`]: the blocks and the CFG. It gives an
//! [`Ssa`]: the same arena in L1 form, plus side tables. The ops of each instruction keep
//! their index, so a run of L1 takes the same steps as a run of L0.
//!
//! | L0 op | L1 op |
//! |---|---|
//! | `Get(loc)` | `Copy` of the value of `loc` at that point |
//! | `Put(loc, x)` | `Nop`. The value `x` becomes the value of `loc`. |
//! | `Ret`, `Call`, `CallInd` | The same op. [`Opts`] gives its location uses and defs. |
//! | `Syscall`, `Intrinsic` | The same op. Its [`Effect`](crate::Effect) gives its uses and defs. |
//!
//! The location uses of an op go to a side table ([`Ssa::uses_at`]). Each location def of an
//! op becomes a new `Get` op after it ([`Ssa::defs_at`]).
//!
//! L1 adds ops outside the instructions. Each added op has an [`Anchor`]. The head of a
//! block holds only `Phi` ops. In L1, a `Get` op gives a value from outside SSA: the
//! location at function entry (anchor `Start`) or the location after an effect op.
//!
//! The function entry is an extra edge into the entry block. So each phi of the entry
//! block has one argument more than the block has predecessors. Its last argument is the
//! entry value.
//!
//! An added op takes the address of its anchor. Its sequence number comes from a counter
//! for each address. Phis use `0xf000` and above, and other added ops use `0x8000` and
//! above.

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::{Fuel, OutOfFuel};

use crate::arena::{Arena, BuildError, InsnSpan};
use crate::graph::{Cfg, Node, rpo};
use crate::interp::Interp;
use crate::loc::{Loc, LocSet, REG_COUNT};
use crate::op::{Arg, Op, OpId, Opc, Val};

mod braun;
mod build;
pub(crate) mod cleanup;
mod edit;

/// The first sequence number of an op that a pass adds.
pub const PASS_SEQ: u16 = 0x8000;

/// The first sequence number of a phi.
pub const PHI_SEQ: u16 = 0xf000;

/// A basic block: a run of instructions of the arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Block {
    /// The index of the first instruction in [`Arena::insns`].
    pub first: u32,
    /// The count of instructions, at least 1.
    pub count: u32,
}

/// The body of a function: its blocks and its CFG. Node `n` of the CFG is block `n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    /// The blocks. Each instruction of the arena is in exactly one block.
    pub blocks: Vec<Block>,
    /// The CFG over the blocks.
    pub cfg: Cfg,
}

/// The locations that the flow ops `Ret`, `Call` and `CallInd` read and write in L1.
///
/// The calling convention gives these sets. The default sets are empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Opts {
    /// The locations that a `Ret` reads.
    pub ret_uses: LocSet,
    /// The locations that a `Call` or `CallInd` reads.
    pub call_uses: LocSet,
    /// The locations that a `Call` or `CallInd` writes.
    pub call_defs: LocSet,
}

impl Opts {
    /// Gives the options that keep the full machine state: a `Ret` and a call read every
    /// register and the flags word. A call writes no location.
    #[must_use]
    pub fn full() -> Self {
        let all: LocSet = (0..REG_COUNT).map(Loc::Reg).chain([Loc::Flags]).collect();
        Self {
            ret_uses: all,
            call_uses: all,
            call_defs: LocSet::EMPTY,
        }
    }
}

/// The place of an op that L1 adds outside the instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Anchor {
    /// The function start, before the entry block. The entry `Get` ops are here.
    Start,
    /// The start of a block. Only `Phi` ops are here.
    Head(Node),
    /// The place before the instruction op with this index.
    Before(u32),
    /// The place after the instruction op with this index.
    After(u32),
    /// The end of a block, before the flow goes to a successor.
    Tail(Node),
}

/// The error of [`build`] and of the passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsaError {
    /// The CFG node count is not the block count.
    BlockCount {
        /// The count of blocks.
        blocks: usize,
        /// The count of CFG nodes.
        nodes: usize,
    },
    /// A block has no instruction, or its instructions are outside the arena.
    BadBlock {
        /// The block.
        block: Node,
    },
    /// An instruction is in no block, or in more than one block.
    InsnCover {
        /// The address of the instruction.
        addr: u64,
    },
    /// An op is not valid L0. Examples: a `Phi`, or a location argument of an op other
    /// than `Get` and `Put`.
    BadOp {
        /// The op.
        at: OpId,
    },
    /// An address has no free sequence number for an added op.
    SeqFull {
        /// The address.
        addr: u64,
    },
    /// The arena has too many ops or values.
    Full,
    /// The work used all of its fuel.
    OutOfFuel,
}

impl fmt::Display for SsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockCount { blocks, nodes } => write!(
                f,
                "The body has {blocks} blocks, but the CFG has {nodes} nodes."
            ),
            Self::BadBlock { block } => write!(
                f,
                "Block {} has no instruction, or its instructions are outside the arena.",
                block.0
            ),
            Self::InsnCover { addr } => write!(
                f,
                "The instruction at {addr:#x} is not in exactly one block."
            ),
            Self::BadOp { at } => write!(f, "The op {:#x}:{} is not valid L0.", at.addr, at.seq),
            Self::SeqFull { addr } => write!(
                f,
                "The address {addr:#x} has no free sequence number for a new op."
            ),
            Self::Full => f.write_str("The arena has too many ops or values."),
            Self::OutOfFuel => f.write_str("The SSA work used all of its fuel."),
        }
    }
}

impl std::error::Error for SsaError {}

impl From<OutOfFuel> for SsaError {
    fn from(_: OutOfFuel) -> Self {
        Self::OutOfFuel
    }
}

impl From<BuildError> for SsaError {
    fn from(_: BuildError) -> Self {
        Self::Full
    }
}

/// The marker of an op outside every block in [`Ssa::op_block`].
pub(crate) const NO_BLOCK: u32 = u32::MAX;

/// An arena in L1 form, with its blocks, its CFG and its side tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssa {
    /// The arena. The instruction ops keep their index.
    pub(crate) arena: Arena,
    /// The blocks of the body.
    pub(crate) blocks: Vec<Block>,
    /// The CFG. A pass can remove edges.
    pub(crate) cfg: Cfg,
    /// The predecessor lists of the CFG, in edge order.
    pub(crate) preds: Vec<Vec<Node>>,
    /// The block of each instruction.
    pub(crate) insn_block: Vec<u32>,
    /// The block of each instruction op, or [`NO_BLOCK`].
    pub(crate) op_block: Vec<u32>,
    /// The added ops of each anchor, in run order.
    pub(crate) anchors: BTreeMap<Anchor, Vec<u32>>,
    /// The anchor of each added op.
    pub(crate) places: BTreeMap<u32, Anchor>,
    /// The location uses of the flow ops.
    pub(crate) uses: BTreeMap<u32, Vec<(Loc, Arg)>>,
    /// The location defs of the flow ops: the values of their `Get` ops.
    pub(crate) defs: BTreeMap<u32, Vec<(Loc, Val)>>,
    /// The next sequence numbers of each address: `[pass ops, phis]`.
    pub(crate) seqs: BTreeMap<u64, [u16; 2]>,
}

impl Ssa {
    /// Gives the arena.
    #[must_use]
    pub const fn arena(&self) -> &Arena {
        &self.arena
    }

    /// Gives the arena for an edit in place. An edit can break the SSA rules, and
    /// [`check`](crate::check::check) then reports it.
    pub const fn arena_mut(&mut self) -> &mut Arena {
        &mut self.arena
    }

    /// Gives the arena and drops the side tables.
    #[must_use]
    pub fn into_arena(self) -> Arena {
        self.arena
    }

    /// Gives the blocks.
    #[must_use]
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// Gives the CFG.
    #[must_use]
    pub const fn cfg(&self) -> &Cfg {
        &self.cfg
    }

    /// Gives the entry block.
    #[must_use]
    pub const fn entry(&self) -> Node {
        self.cfg.entry()
    }

    /// Gives the predecessors of a block in edge order.
    #[must_use]
    pub fn preds(&self, block: Node) -> &[Node] {
        self.preds
            .get(block.index())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Gives the count of phi arguments of a block: one for each predecessor, plus one for
    /// the function entry in the entry block.
    #[must_use]
    pub fn phi_arity(&self, block: Node) -> usize {
        let extra = usize::from(block == self.entry());
        self.preds(block).len().saturating_add(extra)
    }

    /// Gives the address of the first instruction of a block.
    #[must_use]
    pub fn block_addr(&self, block: Node) -> Option<u64> {
        let first = self.blocks.get(block.index())?.first;
        self.arena
            .insns()
            .get(usize::try_from(first).ok()?)
            .map(|s| s.addr)
    }

    /// Gives the block whose first instruction starts at `addr`.
    #[must_use]
    pub fn block_at(&self, addr: u64) -> Option<Node> {
        let index = self.arena.insn_index(addr)?;
        let block = self.block_of_insn(index)?;
        let first = self.blocks.get(block.index())?.first;
        (usize::try_from(first).ok()? == index).then_some(block)
    }

    /// Gives the block of the instruction with this index in [`Arena::insns`].
    #[must_use]
    pub fn block_of_insn(&self, index: usize) -> Option<Node> {
        self.insn_block.get(index).copied().map(Node)
    }

    /// Gives the block of an op: the block of its instruction, or the block of its anchor.
    #[must_use]
    pub fn block_of_op(&self, index: u32) -> Option<Node> {
        if let Some(&block) = self.op_block.get(usize::try_from(index).ok()?) {
            return (block != NO_BLOCK).then_some(Node(block));
        }
        match self.places.get(&index)? {
            Anchor::Start => Some(self.entry()),
            Anchor::Head(b) | Anchor::Tail(b) => Some(*b),
            Anchor::Before(i) | Anchor::After(i) => self.block_of_op(*i),
        }
    }

    /// Tells if the op with this index is an instruction op.
    #[must_use]
    pub fn is_insn_op(&self, index: u32) -> bool {
        usize::try_from(index).is_ok_and(|i| self.op_block.get(i).is_some_and(|&b| b != NO_BLOCK))
    }

    /// Gives the added ops of an anchor in run order.
    #[must_use]
    pub fn anchored(&self, anchor: Anchor) -> &[u32] {
        self.anchors
            .get(&anchor)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Gives the anchor of an added op, or `None` for an instruction op.
    #[must_use]
    pub fn place(&self, index: u32) -> Option<Anchor> {
        self.places.get(&index).copied()
    }

    /// Gives the phi ops of a block.
    #[must_use]
    pub fn phis(&self, block: Node) -> &[u32] {
        self.anchored(Anchor::Head(block))
    }

    /// Gives the location uses of a flow op: each location and its value at the op.
    #[must_use]
    pub fn uses_at(&self, index: u32) -> &[(Loc, Arg)] {
        self.uses.get(&index).map(Vec::as_slice).unwrap_or_default()
    }

    /// Gives the location defs of a flow op: each location and its new value.
    #[must_use]
    pub fn defs_at(&self, index: u32) -> &[(Loc, Val)] {
        self.defs.get(&index).map(Vec::as_slice).unwrap_or_default()
    }

    /// Gives the index of the instruction op with this ID.
    #[must_use]
    pub fn op_index(&self, at: OpId) -> Option<u32> {
        let span = self.arena.insns().get(self.arena.insn_index(at.addr)?)?;
        let seq = u32::from(at.seq);
        (seq < span.count).then(|| span.first.saturating_add(seq))
    }

    /// Gives the L1 ops in run order.
    ///
    /// The order is the anchor `Start`, then each block in reverse postorder, then the
    /// blocks that the entry does not reach, in node order. Inside a block, the order is the
    /// phis, then each instruction op with the ops before and after it, then the tail.
    #[must_use]
    pub fn order(&self) -> Vec<u32> {
        let mut out = self.anchored(Anchor::Start).to_vec();
        for block in self.block_order() {
            self.block_ops(block, &mut out);
        }
        out
    }

    /// Gives the blocks in reverse postorder, then the other blocks in node order.
    #[must_use]
    pub fn block_order(&self) -> Vec<Node> {
        let mut order = rpo(&self.cfg);
        let mut seen = vec![false; self.blocks.len()];
        for n in &order {
            if let Some(flag) = seen.get_mut(n.index()) {
                *flag = true;
            }
        }
        let rest: Vec<Node> = (0..self.blocks.len())
            .filter(|&i| !seen.get(i).copied().unwrap_or(true))
            .filter_map(|i| u32::try_from(i).ok().map(Node))
            .collect();
        order.extend(rest);
        order
    }

    /// Adds the ops of one block in run order to `out`.
    pub(crate) fn block_ops(&self, block: Node, out: &mut Vec<u32>) {
        out.extend_from_slice(self.anchored(Anchor::Head(block)));
        for i in self.insn_op_range(block) {
            out.extend_from_slice(self.anchored(Anchor::Before(i)));
            out.push(i);
            out.extend_from_slice(self.anchored(Anchor::After(i)));
        }
        out.extend_from_slice(self.anchored(Anchor::Tail(block)));
    }

    /// Gives the last instruction of a block.
    #[must_use]
    pub fn last_insn(&self, block: Node) -> Option<InsnSpan> {
        let b = self.blocks.get(block.index())?;
        let last = b.first.checked_add(b.count.checked_sub(1)?)?;
        self.arena.insns().get(usize::try_from(last).ok()?).copied()
    }

    /// Gives the indices of the instruction ops of a block.
    pub(crate) fn insn_op_range(&self, block: Node) -> std::ops::Range<u32> {
        let first = self
            .blocks
            .get(block.index())
            .and_then(|b| self.arena.insns().get(usize::try_from(b.first).ok()?));
        match (first, self.last_insn(block)) {
            (Some(lo), Some(hi)) => lo.first..hi.first.saturating_add(hi.count),
            _ => 0..0,
        }
    }

    /// Follows `Copy` ops that keep the value, and gives the first other argument.
    ///
    /// A `Copy` keeps the value when its input has at most the width of the copy.
    #[must_use]
    pub fn root(&self, arg: Arg) -> Arg {
        let mut cur = arg;
        for _ in 0..=self.arena.ops().len() {
            let Arg::V(v) = cur else {
                return cur;
            };
            let Some(op) = self.live_def(v) else {
                return cur;
            };
            if op.opc != Opc::Copy {
                return cur;
            }
            match op.a[0] {
                Arg::K(imm) if imm.get() == imm.get() & low_mask(op.w) => cur = op.a[0],
                Arg::V(src) if self.value_width(src).is_some_and(|w| w <= op.w) => {
                    cur = op.a[0];
                }
                _ => return cur,
            }
        }
        cur
    }

    /// Gives the width in bits of a value: the output width of its def op.
    ///
    /// A compare and a `Cond` give 1 bit. `Flags`, `FlagsSel` and `FlagsSet` give 16 bits.
    #[must_use]
    pub fn value_width(&self, val: Val) -> Option<u8> {
        let op = self.arena.op(self.arena.def_of(val)?)?;
        Some(out_width(op))
    }

    /// Gives the def op of a value when the op still defines it.
    #[must_use]
    pub fn live_def(&self, val: Val) -> Option<&Op> {
        let index = self.arena.def_of(val)?;
        let op = self.arena.op(index)?;
        (op.out == Some(val) && (self.is_insn_op(index) || self.places.contains_key(&index)))
            .then_some(op)
    }

    /// Gives the values of the location uses of the flow op `at` after an L1 run.
    ///
    /// A value is `None` when the run did not compute it.
    #[must_use]
    pub fn observe(&self, interp: &Interp<'_>, at: OpId) -> Vec<(Loc, Option<u128>)> {
        let Some(index) = self.op_index(at) else {
            return Vec::new();
        };
        self.uses_at(index)
            .iter()
            .map(|&(loc, arg)| {
                let value = match arg {
                    Arg::K(imm) => Some(u128::from(imm.get())),
                    Arg::V(v) => interp.val(v),
                    Arg::Nil | Arg::L(_) => None,
                };
                (loc, value)
            })
            .collect()
    }
}

/// Gives the output width of an op in bits.
#[must_use]
pub fn out_width(op: &Op) -> u8 {
    match op.opc {
        Opc::Cond => 1,
        Opc::Flags | Opc::FlagsSel | Opc::FlagsSet => 16,
        opc if opc.is_compare() => 1,
        _ => op.w,
    }
}

/// The value mask of a width from 0 to 128 bits, as a 64-bit constant mask.
pub(crate) const fn low_mask(w: u8) -> u64 {
    if w >= 64 { u64::MAX } else { (1u64 << w) - 1 }
}

/// Makes the L1 form of `arena` over `body`.
///
/// The build checks the body. It reads the locations of each block, then it reads the
/// values at block starts with phis (Braun, all blocks sealed). Last, it removes the
/// redundant phis with the SCC method of Braun, so the result is minimal for a reducible
/// CFG. No step recurses, so a deep CFG does not overflow the thread stack. Each op and each
/// step of a walk takes one unit of `fuel`.
///
/// # Errors
///
/// Returns [`SsaError::BlockCount`], [`SsaError::BadBlock`] and [`SsaError::InsnCover`] for a
/// bad body. Returns [`SsaError::BadOp`] for an op that is not valid L0. Returns
/// [`SsaError::SeqFull`] and [`SsaError::Full`] when the arena cannot take an op. Returns
/// [`SsaError::OutOfFuel`] when the fuel runs out.
pub fn build(arena: Arena, body: Body, opts: &Opts, fuel: &mut Fuel) -> Result<Ssa, SsaError> {
    build::build(arena, body, opts, fuel)
}
