//! Stack tracking and frames (design Section 7.9).
//!
//! [`track`] runs a forward dataflow over L0. A value is an offset from `SP0`, the stack
//! pointer at entry, a value that does not come from the stack pointer, or `Top`. A merge of
//! two offsets that differ gives `Top`. A call adds 8, the pop of the return address, and the
//! call writes the registers that the callee does not keep. A `Load` or a `Store` at `SP0 + k`
//! is an access to the slot `k`.
//!
//! An address escapes when an op stores it or passes it to a call in an argument register.
//! It also escapes in arithmetic that is not a constant offset. Then every slot from its
//! offset up escapes. An `Intrinsic` with a memory effect at `SP0 + k` makes every slot in
//! `[k, k + size)` escape. With an unknown offset from `SP0`, every slot escapes (AC-207).
//!
//! [`rewrite`] puts `Get` and `Put` of `Stack(k)` in place of the accesses of a slot when
//! three conditions are true. The slot does not escape. It has one width of at most 8 bytes.
//! No other access overlaps it. An escaped slot stays in memory, so no pass keeps a stale
//! value.
//!
//! [`cfa_check`] compares the tracked offset at each call site with the CFA row of the FDE
//! (AC-091). A CFA of `rsp + c` needs the offset `8 - c` for `rsp`. A CFA of `rbp + c` needs
//! the offset `8 - c` for `rbp`. A known offset that differs is a [`Mismatch`]: the function
//! gets `W_SP_MISMATCH` there. A `Top` value gives no compare: the tracking already gave up,
//! for example after `and rsp, -16` in `_start`.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Fuel, OutOfFuel};
use ghidorah_ir::ssa::Body;
use ghidorah_ir::{Arena, Arg, Loc, MemEffect, Node, Op, Opc, Val, rpo};

mod cfa;

pub use self::cfa::{Mismatch, cfa_check, cfa_rule, run, spec};

/// The DWARF number of `rsp`.
pub const DWARF_RSP: u16 = 7;

/// The DWARF number of `rbp`.
pub const DWARF_RBP: u16 = 6;

/// The number of tracked general registers.
const REGS: usize = 16;

/// The register number of `rsp`.
const RSP: usize = 4;

/// The register number of `rbp`.
const RBP: usize = 5;

/// The registers that a call writes: `rax`, `rcx`, `rdx`, `rsi`, `rdi` and `r8` to `r11`.
const CALL_DEFS: [usize; 9] = [0, 1, 2, 6, 7, 8, 9, 10, 11];

/// The argument registers of a call: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` and `r10`.
const ARG_REGS: [usize; 7] = [7, 6, 2, 1, 8, 9, 10];

/// The callee-saved registers: `rbx`, `rbp` and `r12` to `r15`.
const SAVED: [usize; 6] = [3, 5, 12, 13, 14, 15];

/// The value of the stack pointer, or of a value that comes from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Sp {
    /// No path reaches the point yet.
    #[default]
    Unset,
    /// The value is `SP0 + k`.
    At(i64),
    /// The value does not come from the stack pointer.
    Other,
    /// The value can come from the stack pointer, with an unknown offset.
    Top,
}

impl Sp {
    /// Gives the merge of two values.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unset, x) | (x, Self::Unset) => x,
            (Self::At(a), Self::At(b)) if a == b => Self::At(a),
            (Self::Other, Self::Other) => Self::Other,
            _ => Self::Top,
        }
    }

    /// Gives the offset of a known value.
    #[must_use]
    pub const fn offset(self) -> Option<i64> {
        match self {
            Self::At(k) => Some(k),
            _ => None,
        }
    }

    /// Tells if the value can come from the stack pointer.
    const fn is_stack(self) -> bool {
        matches!(self, Self::At(_) | Self::Top)
    }
}

/// One frame access: the slot offset and the width in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Access {
    /// The offset from `SP0`.
    pub off: i64,
    /// The width in bytes.
    pub size: u8,
}

/// The stack frame of a function.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Frame {
    /// The stack pointer before each instruction, by address.
    pub sp: BTreeMap<u64, Sp>,
    /// The `rbp` value before each instruction, by address.
    pub bp: BTreeMap<u64, Sp>,
    /// The frame accesses by op index.
    pub access: BTreeMap<u32, Access>,
    /// The escaped byte ranges `[from, to)` of the frame.
    pub escaped: Vec<(i64, i64)>,
    /// Every slot escapes.
    pub all_escape: bool,
    /// The callee-saved registers that the entry block pushes, with their slots.
    pub saved: Vec<(Loc, i64)>,
}

impl Frame {
    /// Gives the offset of the stack pointer before the instruction at `addr`.
    #[must_use]
    pub fn sp_at(&self, addr: u64) -> Option<i64> {
        self.sp.get(&addr).and_then(|s| s.offset())
    }

    /// Tells if a byte of `[off, off + size)` escapes.
    #[must_use]
    pub fn escapes(&self, off: i64, size: u32) -> bool {
        let end = off.saturating_add(i64::from(size.max(1)));
        self.all_escape || self.escaped.iter().any(|(a, b)| off < *b && *a < end)
    }

    /// Gives the lowest offset that the function accesses: the size of its locals.
    #[must_use]
    pub fn low(&self) -> i64 {
        self.access
            .values()
            .map(|a| a.off)
            .min()
            .unwrap_or(0)
            .min(0)
    }

    /// Gives the stack parameter slots: the read offsets at `first` and above.
    #[must_use]
    pub fn stack_args(&self, first: i64) -> BTreeSet<i64> {
        self.access
            .values()
            .filter(|a| a.off >= first)
            .map(|a| a.off)
            .collect()
    }
}

/// The register state at one program point.
type Regs = [Sp; REGS];

/// The register state at function entry: `rsp` is `SP0`.
fn entry_regs() -> Regs {
    let mut r = [Sp::Other; REGS];
    r[RSP] = Sp::At(0);
    r
}

/// Gives the merge of two states.
fn join(a: &Regs, b: &Regs) -> Regs {
    let mut out = *a;
    for (o, x) in out.iter_mut().zip(b) {
        *o = o.join(*x);
    }
    out
}

/// Gives the tracked register of a location.
fn reg(loc: Loc) -> Option<usize> {
    match loc {
        Loc::Reg(n) => Some(usize::from(n)).filter(|n| *n < REGS),
        Loc::Flags | Loc::Stack(_) => None,
    }
}

/// The transfer of one block, with the records of the final pass.
struct Transfer<'a> {
    arena: &'a Arena,
    regs: Regs,
    vals: BTreeMap<Val, Sp>,
    /// `Some` in the final pass: the frame that gets the records.
    frame: Option<&'a mut Frame>,
    /// The callee-saved registers that the entry block did not write yet.
    fresh: BTreeSet<usize>,
    entry: bool,
}

impl Transfer<'_> {
    /// Gives the value of an argument.
    fn val(&self, a: Arg) -> Sp {
        match a {
            Arg::V(v) => self.vals.get(&v).copied().unwrap_or(Sp::Other),
            Arg::K(_) | Arg::Nil | Arg::L(_) => Sp::Other,
        }
    }

    /// Records that the frame from `v` up escapes.
    fn escape(&mut self, v: Sp) {
        let Some(frame) = self.frame.as_deref_mut() else {
            return;
        };
        match v {
            Sp::At(k) => frame.escaped.push((k, i64::MAX)),
            Sp::Top => frame.all_escape = true,
            Sp::Other | Sp::Unset => {}
        }
    }

    /// Records a frame access of the op `index` at the address `addr`.
    fn access(&mut self, index: u32, addr: Sp, w: u8) {
        if let (Some(frame), Sp::At(off)) = (self.frame.as_deref_mut(), addr) {
            frame.access.insert(index, Access { off, size: w / 8 });
        }
    }

    /// Gives the value of a data op.
    fn data(&mut self, op: &Op) -> Sp {
        let [lhs, rhs, _] = [self.val(op.a[0]), self.val(op.a[1]), self.val(op.a[2])];
        let imm = |a: Arg| a.as_k();
        match op.opc {
            Opc::Copy => lhs,
            _ if !lhs.is_stack() && !rhs.is_stack() => Sp::Other,
            Opc::Add if op.w == 64 => match (lhs, rhs, imm(op.a[0]), imm(op.a[1])) {
                (Sp::At(off), _, _, Some(n)) | (_, Sp::At(off), Some(n), _) => {
                    Sp::At(off.wrapping_add(n.cast_signed()))
                }
                _ => {
                    self.escape(lhs);
                    self.escape(rhs);
                    Sp::Top
                }
            },
            Opc::Sub if op.w == 64 => match (lhs, imm(op.a[1])) {
                (Sp::At(off), Some(n)) => Sp::At(off.wrapping_sub(n.cast_signed())),
                _ if lhs.is_stack() && rhs.is_stack() => Sp::Other,
                _ => {
                    self.escape(lhs);
                    Sp::Top
                }
            },
            Opc::Flags
            | Opc::Cond
            | Opc::Eq
            | Opc::Ne
            | Opc::ULt
            | Opc::ULe
            | Opc::SLt
            | Opc::SLe
            | Opc::TestZ
            | Opc::TestNZ => Sp::Other,
            Opc::And => Sp::Top,
            _ => {
                self.escape(lhs);
                self.escape(rhs);
                Sp::Top
            }
        }
    }

    /// Runs one op.
    fn op(&mut self, index: u32, op: &Op) {
        let out = match op.opc {
            Opc::Get => match op.a[0].as_loc().and_then(reg) {
                Some(r) => self.regs[r],
                None => Sp::Other,
            },
            Opc::Put => {
                let v = self.val(op.a[1]);
                if let Some(r) = op.a[0].as_loc().and_then(reg) {
                    self.regs[r] = v;
                    self.fresh.remove(&r);
                }
                return;
            }
            Opc::Load => {
                self.access(index, self.val(op.a[0]), op.w);
                Sp::Other
            }
            Opc::Store => {
                let addr = self.val(op.a[0]);
                self.access(index, addr, op.w);
                let v = self.val(op.a[1]);
                self.escape(v);
                self.saved(op, addr);
                return;
            }
            Opc::Call | Opc::CallInd => {
                for r in ARG_REGS {
                    self.escape(self.regs[r]);
                }
                self.regs[RSP] = match self.regs[RSP] {
                    Sp::At(k) => Sp::At(k.wrapping_add(8)),
                    other => other,
                };
                for r in CALL_DEFS {
                    self.regs[r] = Sp::Other;
                }
                return;
            }
            Opc::Syscall | Opc::Intrinsic => {
                self.effect(op);
                return;
            }
            _ if op.opc.has_out() => self.data(op),
            _ => return,
        };
        if let Some(v) = op.out {
            self.vals.insert(v, out);
        }
    }

    /// Runs a `Syscall` or `Intrinsic` op: its argument registers, its memory effect and its
    /// defs.
    fn effect(&mut self, op: &Op) {
        let Some(effect) = self.arena.effect(op).copied() else {
            return;
        };
        if op.opc == Opc::Syscall {
            for r in ARG_REGS {
                self.escape(self.regs[r]);
            }
        }
        let size = match effect.mem {
            MemEffect::Read { size }
            | MemEffect::Write { size }
            | MemEffect::ReadWrite { size } => Some(size),
            MemEffect::None => None,
        };
        if let Some(size) = size
            && let Some(frame) = self.frame.as_deref_mut()
        {
            match op.a[1].as_v().and_then(|v| self.vals.get(&v)) {
                Some(Sp::At(k)) if size > 0 => {
                    frame.escaped.push((*k, k.saturating_add(i64::from(size))));
                }
                Some(Sp::At(k)) => frame.escaped.push((*k, i64::MAX)),
                Some(Sp::Top) => frame.all_escape = true,
                _ => {}
            }
        }
        for loc in effect.defs.iter() {
            if let Some(r) = reg(loc) {
                self.regs[r] = if r == RSP { Sp::Top } else { Sp::Other };
            }
        }
    }

    /// Records a push of a callee-saved register in the entry block.
    fn saved(&mut self, op: &Op, addr: Sp) {
        if !self.entry {
            return;
        }
        let (Sp::At(k), Some(v)) = (addr, op.a[1].as_v()) else {
            return;
        };
        let Some(def) = self.arena.def_of(v).and_then(|d| self.arena.op(d)) else {
            return;
        };
        let Some(r) = (def.opc == Opc::Get)
            .then(|| def.a[0].as_loc().and_then(reg))
            .flatten()
        else {
            return;
        };
        if SAVED.contains(&r)
            && self.fresh.remove(&r)
            && let Some(frame) = self.frame.as_deref_mut()
        {
            let n = u16::try_from(r).unwrap_or(0);
            frame.saved.push((Loc::Reg(n), k));
        }
    }
}

/// Runs the ops of the block `node` from the state `regs`. Gives the state at its end.
fn run_block(
    arena: &Arena,
    body: &Body,
    node: Node,
    regs: Regs,
    frame: Option<&mut Frame>,
    fuel: &mut Fuel,
) -> Result<Regs, OutOfFuel> {
    let entry = node == body.cfg.entry();
    let mut step = Transfer {
        arena,
        regs,
        vals: BTreeMap::new(),
        frame,
        fresh: SAVED.into_iter().collect(),
        entry,
    };
    let Some(block) = body.blocks.get(node.index()) else {
        return Ok(step.regs);
    };
    let first = usize::try_from(block.first).unwrap_or(usize::MAX);
    let count = usize::try_from(block.count).unwrap_or(0);
    for span in arena.insns().iter().skip(first).take(count) {
        if let Some(frame) = step.frame.as_deref_mut() {
            frame.sp.insert(span.addr, step.regs[RSP]);
            frame.bp.insert(span.addr, step.regs[RBP]);
        }
        for k in 0..span.count {
            fuel.tick()?;
            let Some(index) = span.first.checked_add(k) else {
                continue;
            };
            if let Some(op) = arena.op(index).copied() {
                step.op(index, &op);
            }
        }
    }
    Ok(step.regs)
}

/// Tracks the stack of the L0 body. Each op takes one unit of `fuel` for each pass.
///
/// # Errors
///
/// Returns [`OutOfFuel`] when `fuel` runs out.
pub fn track(arena: &Arena, body: &Body, fuel: &mut Fuel) -> Result<Frame, OutOfFuel> {
    let order = rpo(&body.cfg);
    let preds = body.cfg.preds();
    let entry = body.cfg.entry();
    let mut out: BTreeMap<Node, Regs> = BTreeMap::new();
    let in_of = |out: &BTreeMap<Node, Regs>, node: Node| -> Regs {
        let mut regs = if node == entry {
            entry_regs()
        } else {
            [Sp::Unset; REGS]
        };
        for p in preds.get(node.index()).into_iter().flatten() {
            if let Some(o) = out.get(p) {
                regs = join(&regs, o);
            }
        }
        regs
    };
    let rounds = order.len().saturating_mul(4).saturating_add(8);
    for _ in 0..rounds {
        let mut changed = false;
        for node in &order {
            let regs = in_of(&out, *node);
            let end = run_block(arena, body, *node, regs, None, fuel)?;
            if out.get(node) != Some(&end) {
                out.insert(*node, end);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut frame = Frame::default();
    for node in &order {
        let regs = in_of(&out, *node);
        let _ = run_block(arena, body, *node, regs, Some(&mut frame), fuel)?;
    }
    frame.escaped.sort_unstable();
    frame.escaped.dedup();
    Ok(frame)
}

/// Puts `Get` and `Put` of `Stack(k)` in place of the accesses of the slots of `frame` that
/// the module rules let stay in registers. Gives the count of changed ops.
pub fn rewrite(arena: &mut Arena, frame: &Frame) -> u64 {
    if frame.all_escape {
        return 0;
    }
    let mut slots: BTreeMap<i64, BTreeSet<u8>> = BTreeMap::new();
    for a in frame.access.values() {
        slots.entry(a.off).or_default().insert(a.size);
    }
    let mut good: BTreeSet<i64> = BTreeSet::new();
    let mut prev_end: Option<i64> = None;
    let list: Vec<(i64, BTreeSet<u8>)> = slots.into_iter().collect();
    for (i, (off, sizes)) in list.iter().enumerate() {
        let size = sizes.iter().next_back().copied().unwrap_or(0);
        let end = off.saturating_add(i64::from(size));
        let next = list.get(i.saturating_add(1)).map(|(o, _)| *o);
        let clear = prev_end.is_none_or(|e| e <= *off) && next.is_none_or(|n| end <= n);
        if sizes.len() == 1
            && (1..=8).contains(&size)
            && clear
            && !frame.escapes(*off, u32::from(size))
            && i32::try_from(*off).is_ok()
        {
            good.insert(*off);
        }
        prev_end = Some(prev_end.map_or(end, |e| e.max(end)));
    }
    let mut count = 0u64;
    for (index, a) in &frame.access {
        if !good.contains(&a.off) {
            continue;
        }
        let Ok(k) = i32::try_from(a.off) else {
            continue;
        };
        let Some(op) = usize::try_from(*index)
            .ok()
            .and_then(|i| arena.ops_mut().get_mut(i))
        else {
            continue;
        };
        let loc = Arg::L(Loc::Stack(k));
        match op.opc {
            Opc::Load => {
                op.opc = Opc::Get;
                op.a = [loc, Arg::Nil, Arg::Nil];
            }
            Opc::Store => {
                op.opc = Opc::Put;
                op.a = [loc, op.a[1], Arg::Nil];
            }
            _ => continue,
        }
        count = count.saturating_add(1);
    }
    count
}
