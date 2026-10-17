//! The op arena and its builder (design Section 6.1).
//!
//! An [`Arena`] holds the ops of a program in instruction order. Each instruction has an
//! [`InsnSpan`]: its address, its length and its run of ops. The ops of one instruction
//! have the sequence numbers 0, 1, 2 and so on. The interpreter goes from the end of an
//! instruction to the address after it.
//!
//! The arena also holds two side tables: the [`Effect`] of each `Syscall` and `Intrinsic`
//! op, and the argument list of each `Phi` op of L1.
//!
//! [`Builder`] makes an arena. A lifter calls [`Builder::begin`] for each instruction,
//! then one call for each op.

use std::fmt;

use crate::loc::Loc;
use crate::op::{Arg, Cc, Effect, FlagOp, Op, OpId, Opc, Val};

/// The largest sequence number of a lifted op. The passes use `0x8000` and above.
pub const MAX_LIFT_SEQ: u16 = 0x7fff;

/// The widest value in bits.
pub const MAX_WIDTH: u8 = 128;

/// The ops of one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InsnSpan {
    /// The address of the instruction.
    pub addr: u64,
    /// The length of the instruction in bytes, at least 1.
    pub len: u8,
    /// The index of the first op of the instruction.
    pub first: u32,
    /// The count of ops of the instruction.
    pub count: u32,
}

impl InsnSpan {
    /// Gives the address after the instruction, or `None` at the end of the address space.
    #[must_use]
    pub fn next_addr(&self) -> Option<u64> {
        self.addr.checked_add(u64::from(self.len))
    }
}

/// The error of a [`Builder`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    /// An op came before the first [`Builder::begin`].
    NoInsn,
    /// An instruction address is not above the address of the instruction before it.
    OutOfOrder {
        /// The address of the new instruction.
        addr: u64,
    },
    /// An instruction has a length of 0.
    ZeroLength {
        /// The address of the instruction.
        addr: u64,
    },
    /// An instruction has more ops than [`MAX_LIFT_SEQ`] allows.
    TooManyOps {
        /// The address of the instruction.
        addr: u64,
    },
    /// The arena has more values or ops than a `u32` can count.
    Full,
    /// An op has a width of 0 or above [`MAX_WIDTH`].
    BadWidth {
        /// The opcode.
        opc: Opc,
        /// The width.
        w: u8,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInsn => f.write_str("An op comes before the first instruction."),
            Self::OutOfOrder { addr } => write!(
                f,
                "The instruction at {addr:#x} is not above the instruction before it."
            ),
            Self::ZeroLength { addr } => {
                write!(f, "The instruction at {addr:#x} has a length of 0.")
            }
            Self::TooManyOps { addr } => {
                write!(f, "The instruction at {addr:#x} has too many ops.")
            }
            Self::Full => f.write_str("The arena has too many ops or values."),
            Self::BadWidth { opc, w } => write!(f, "The {opc} op has a bad width of {w} bits."),
        }
    }
}

impl std::error::Error for BuildError {}

/// The ops of a program in instruction order, with their side tables.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arena {
    ops: Vec<Op>,
    insns: Vec<InsnSpan>,
    effects: Vec<Effect>,
    phis: Vec<Vec<Arg>>,
    defs: Vec<u32>,
}

impl Arena {
    /// Gives all ops. The ops of the instructions come first, in address order.
    #[must_use]
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// Gives all ops for an edit in place. An edit keeps the count of ops.
    pub fn ops_mut(&mut self) -> &mut [Op] {
        &mut self.ops
    }

    /// Gives the op at `index`.
    #[must_use]
    pub fn op(&self, index: u32) -> Option<&Op> {
        self.ops.get(usize::try_from(index).ok()?)
    }

    /// Gives the instructions in address order.
    #[must_use]
    pub fn insns(&self) -> &[InsnSpan] {
        &self.insns
    }

    /// Gives the index of the instruction at `addr`, or `None`.
    #[must_use]
    pub fn insn_index(&self, addr: u64) -> Option<usize> {
        self.insns.binary_search_by_key(&addr, |s| s.addr).ok()
    }

    /// Gives the ops of the instruction at `addr`. An address without an instruction gives
    /// no op.
    #[must_use]
    pub fn insn_ops(&self, addr: u64) -> &[Op] {
        self.insn_index(addr)
            .and_then(|i| self.insns.get(i))
            .and_then(|span| self.span_ops(span))
            .unwrap_or_default()
    }

    /// Gives the ops of a span, or `None` when the span is outside the arena.
    #[must_use]
    pub fn span_ops(&self, span: &InsnSpan) -> Option<&[Op]> {
        let first = usize::try_from(span.first).ok()?;
        let end = first.checked_add(usize::try_from(span.count).ok()?)?;
        self.ops.get(first..end)
    }

    /// Gives the effect of a `Syscall` or `Intrinsic` op, or `None`.
    #[must_use]
    pub fn effect(&self, op: &Op) -> Option<&Effect> {
        match op.opc {
            Opc::Syscall | Opc::Intrinsic => {
                let index = usize::try_from(op.a[0].as_k()?).ok()?;
                self.effects.get(index)
            }
            _ => None,
        }
    }

    /// Gives the argument list of a `Phi` op, or `None`.
    #[must_use]
    pub fn phi_args(&self, op: &Op) -> Option<&[Arg]> {
        match op.opc {
            Opc::Phi => {
                let index = usize::try_from(op.a[0].as_k()?).ok()?;
                self.phis.get(index).map(Vec::as_slice)
            }
            _ => None,
        }
    }

    /// Gives the argument list of a `Phi` op for an edit, or `None`.
    pub fn phi_args_mut(&mut self, index: u32) -> Option<&mut Vec<Arg>> {
        self.phis.get_mut(usize::try_from(index).ok()?)
    }

    /// Adds a phi argument list. Gives its index for argument 0 of a `Phi` op.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::Full`] when the count of lists does not fit in a `u32`.
    pub fn push_phi_args(&mut self, args: Vec<Arg>) -> Result<u32, BuildError> {
        let index = u32::try_from(self.phis.len()).map_err(|_| BuildError::Full)?;
        self.phis.push(args);
        Ok(index)
    }

    /// Gives the count of values.
    #[must_use]
    pub fn val_count(&self) -> usize {
        self.defs.len()
    }

    /// Gives the index of the op that defines `val`, or `None`.
    #[must_use]
    pub fn def_of(&self, val: Val) -> Option<u32> {
        self.defs.get(usize::try_from(val.0).ok()?).copied()
    }

    /// Adds an op after all other ops, outside each instruction (an L1 phi or a pass op).
    ///
    /// The op gets a new output value when `opc` has an output. The call replaces
    /// `op.out`.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::Full`] when the arena is full, and [`BuildError::BadWidth`]
    /// for a bad width.
    pub fn push_op(&mut self, mut op: Op) -> Result<(u32, Option<Val>), BuildError> {
        check_width(op.opc, op.w)?;
        let index = u32::try_from(self.ops.len()).map_err(|_| BuildError::Full)?;
        op.out = if op.opc.has_out() {
            Some(self.alloc_val(index)?)
        } else {
            None
        };
        self.ops.push(op);
        Ok((index, op.out))
    }

    /// Makes a new value with its def at op `index`.
    fn alloc_val(&mut self, index: u32) -> Result<Val, BuildError> {
        let val = u32::try_from(self.defs.len()).map_err(|_| BuildError::Full)?;
        self.defs.push(index);
        Ok(Val(val))
    }

    /// Adds an effect to the side table. Gives its index.
    fn push_effect(&mut self, effect: Effect) -> u64 {
        let index = u64::try_from(self.effects.len()).unwrap_or(u64::MAX);
        self.effects.push(effect);
        index
    }
}

/// Checks the width of an op: 1 to 128 bits for an op with an output, `Put` and `Store`,
/// and at most 128 bits for the others.
const fn check_width(opc: Opc, w: u8) -> Result<(), BuildError> {
    let needs_bits = opc.has_out() || matches!(opc, Opc::Put | Opc::Store);
    if w > MAX_WIDTH || (needs_bits && w == 0) {
        Err(BuildError::BadWidth { opc, w })
    } else {
        Ok(())
    }
}

/// The builder of an [`Arena`].
#[derive(Debug, Default)]
pub struct Builder {
    arena: Arena,
}

impl Builder {
    /// Makes an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts the instruction at `addr` with `len` bytes. It closes the instruction before it.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::OutOfOrder`] when `addr` is not above the address before it,
    /// and [`BuildError::ZeroLength`] when `len` is 0.
    pub fn begin(&mut self, addr: u64, len: u8) -> Result<(), BuildError> {
        if len == 0 {
            return Err(BuildError::ZeroLength { addr });
        }
        if self
            .arena
            .insns
            .last()
            .is_some_and(|last| addr <= last.addr)
        {
            return Err(BuildError::OutOfOrder { addr });
        }
        let first = u32::try_from(self.arena.ops.len()).map_err(|_| BuildError::Full)?;
        self.arena.insns.push(InsnSpan {
            addr,
            len,
            first,
            count: 0,
        });
        Ok(())
    }

    /// Adds an op to the last instruction. Gives the output value of an opcode with an output.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::NoInsn`] before the first instruction, [`BuildError::BadWidth`]
    /// for a width of 0 or above 128 on an op with an output, [`BuildError::TooManyOps`]
    /// and [`BuildError::Full`].
    pub fn push(
        &mut self,
        opc: Opc,
        w: u8,
        sub: u8,
        a: [Arg; 3],
    ) -> Result<Option<Val>, BuildError> {
        let span = *self.arena.insns.last().ok_or(BuildError::NoInsn)?;
        let seq = u16::try_from(span.count)
            .ok()
            .filter(|&seq| seq <= MAX_LIFT_SEQ)
            .ok_or(BuildError::TooManyOps { addr: span.addr })?;
        let op = Op {
            id: OpId {
                addr: span.addr,
                seq,
            },
            opc,
            w,
            sub,
            out: None,
            a,
        };
        let (_, out) = self.arena.push_op(op)?;
        if let Some(last) = self.arena.insns.last_mut() {
            last.count = span.count.saturating_add(1);
        }
        Ok(out)
    }

    /// Adds an op that has an output, and gives the output value.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn value(&mut self, opc: Opc, w: u8, sub: u8, a: [Arg; 3]) -> Result<Val, BuildError> {
        self.push(opc, w, sub, a)?
            .ok_or(BuildError::BadWidth { opc, w })
    }

    /// Adds `Get(loc)` at the width of `loc`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn get(&mut self, loc: Loc) -> Result<Val, BuildError> {
        self.value(Opc::Get, loc.width(), 0, [Arg::L(loc), Arg::Nil, Arg::Nil])
    }

    /// Adds `Put(loc, value)` at the width of `loc`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn put(&mut self, loc: Loc, value: Arg) -> Result<(), BuildError> {
        self.push(Opc::Put, loc.width(), 0, [Arg::L(loc), value, Arg::Nil])
            .map(|_| ())
    }

    /// Adds an op with one input at width `w`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn unary(&mut self, opc: Opc, w: u8, x: Arg) -> Result<Val, BuildError> {
        self.value(opc, w, 0, [x, Arg::Nil, Arg::Nil])
    }

    /// Adds an op with two inputs at width `w`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn binary(&mut self, opc: Opc, w: u8, x: Arg, y: Arg) -> Result<Val, BuildError> {
        self.value(opc, w, 0, [x, y, Arg::Nil])
    }

    /// Adds a `Load` of `w` bits at `addr`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn load(&mut self, w: u8, addr: Arg) -> Result<Val, BuildError> {
        self.value(Opc::Load, w, 0, [addr, Arg::Nil, Arg::Nil])
    }

    /// Adds a `Store` of `w` bits of `value` at `addr`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn store(&mut self, w: u8, addr: Arg, value: Arg) -> Result<(), BuildError> {
        self.push(Opc::Store, w, 0, [addr, value, Arg::Nil])
            .map(|_| ())
    }

    /// Adds `ZExt` (`signed` is false) or `SExt` from `from` bits to `w` bits.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn extend(&mut self, signed: bool, w: u8, from: u8, x: Arg) -> Result<Val, BuildError> {
        let opc = if signed { Opc::SExt } else { Opc::ZExt };
        self.value(opc, w, from, [x, Arg::Nil, Arg::Nil])
    }

    /// Adds `Extract`: `w` bits of `x` from bit `lo`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn extract(&mut self, w: u8, x: Arg, lo: u8) -> Result<Val, BuildError> {
        self.value(Opc::Extract, w, 0, [x, Arg::k(u64::from(lo)), Arg::Nil])
    }

    /// Adds `Insert`: `part` of `part_w` bits into `base` of `w` bits at bit `lo`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn insert(
        &mut self,
        w: u8,
        base: Arg,
        part: Arg,
        part_w: u8,
        lo: u8,
    ) -> Result<Val, BuildError> {
        self.value(Opc::Insert, w, part_w, [base, part, Arg::k(u64::from(lo))])
    }

    /// Adds the flag thunk `Flags(op, a, b, c)` at operand width `w`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn flags(&mut self, op: FlagOp, w: u8, a: Arg, b: Arg, c: Arg) -> Result<Val, BuildError> {
        self.value(Opc::Flags, w, op.code(), [a, b, c])
    }

    /// Adds `Cond(cc, flags)`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn cond(&mut self, cc: Cc, flags: Arg) -> Result<Val, BuildError> {
        self.value(Opc::Cond, 1, cc.code(), [flags, Arg::Nil, Arg::Nil])
    }

    /// Adds a flow op with up to two arguments (`Jump`, `CJump`, `Call`, `Ret` and others).
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn flow(&mut self, opc: Opc, x: Arg, y: Arg) -> Result<(), BuildError> {
        let w = if matches!(opc, Opc::Ret | Opc::Unimpl | Opc::Nop) {
            0
        } else {
            64
        };
        self.push(opc, w, 0, [x, y, Arg::Nil]).map(|_| ())
    }

    /// Adds a `Syscall` (`addr` is `Nil`) or an `Intrinsic` op with its effect.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Builder::push`].
    pub fn effect_op(&mut self, opc: Opc, effect: Effect, addr: Arg) -> Result<(), BuildError> {
        if self.arena.insns.is_empty() {
            return Err(BuildError::NoInsn);
        }
        let index = self.arena.push_effect(effect);
        self.push(opc, 64, 0, [Arg::k(index), addr, Arg::Nil])
            .map(|_| ())
    }

    /// Gives the arena.
    #[must_use]
    pub fn finish(self) -> Arena {
        self.arena
    }
}

/// Makes an op with no output value. [`Arena::push_op`] gives the output value.
#[must_use]
pub const fn op_at(id: OpId, opc: Opc, w: u8, sub: u8, a: [Arg; 3]) -> Op {
    Op {
        id,
        opc,
        w,
        sub,
        out: None,
        a,
    }
}
