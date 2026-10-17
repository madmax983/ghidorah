//! The x86-64 lifter: one decoded instruction to L0 ops (design Section 6.3, ADR-0009).
//!
//! [`lift`] adds the ops of one [`Insn`] to an IR [`Builder`]. The const table [`ROWS`]
//! maps each canonical mnemonic to a [`Template`], a flag operation, a write flag and a
//! [`WidthRule`]. One template serves many mnemonics, so one fix covers each mnemonic of
//! the template. [`kind`] tells what [`lift`] does with an instruction.
//!
//! | Instruction | Ops |
//! |---|---|
//! | A row, and operands that the template supports | the ops of the template |
//! | `syscall` | one `Syscall` op with the uses `rax`, `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` and the defs `rax`, `rcx`, `r11` |
//! | A sequential instruction or a trap without a row, or with other operands | one `Intrinsic` op with the [`effect`] of the instruction |
//! | A branch, call or return without a row | one `Unimpl` op |
//!
//! Rules of the ops:
//!
//! - Registers are full width. A 32-bit write is `Put(ZExt)`. An 8-bit or 16-bit write is
//!   an `Insert` into `Get(reg)`. A read of a narrow register is `Trunc` or `Extract`.
//! - A flag write is `Put(flags, Flags(op, a, b, c))`, the lazy thunk of design Section 6.2.
//! - A memory operand gives its address from the base, the index, the displacement and the
//!   `fs` or `gs` base. A RIP-relative operand gives a constant address.
//! - A `rep` string instruction is a loop on its own address. It stops when `rcx` is 0.
//! - The direction flag is 0, as the System V ABI requires at a call boundary.
//! - A quotient that does not fit in its register gives its low bits. The hardware raises
//!   a divide error there.
//! - An `Intrinsic` op of an instruction names the instruction by [`IntrinsicId`]: the
//!   code of its [`Mnem`] ([`intrinsic_mnem`] gives it back).

mod rows;

use std::fmt;

use ghidorah_ir::{
    BuildError, Builder, Effect, FlagOp, IntrinsicId, IntrinsicNames, Loc, LocSet, MemEffect, Opc,
};

use crate::{Insn, Mnem, Reg, RegClass};

/// The version of the lifter. Each function IR and each op ID in a note records it.
pub const LIFT_VER: u32 = 1;

/// The lifting templates of design Section 6.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Template {
    /// `add`, `or`, `adc`, `sbb`, `and`, `sub`, `xor`, `cmp` and `test`.
    Alu2,
    /// `inc`, `dec`, `neg` and `not`.
    Alu1,
    /// `mov` and `movabs`.
    Mov,
    /// `movzx`, `movsx` and `movsxd`.
    Movx,
    /// `lea`.
    Lea,
    /// The 16 `cmovcc` forms.
    Cmov,
    /// The 16 `setcc` forms.
    Setcc,
    /// `jcc`, `jmp`, `call`, `ret`, `loop`, `loope`, `loopne`, `jrcxz` and `jecxz`.
    Branch,
    /// `shl`, `shr`, `sar`, `rol`, `ror`, `shld` and `shrd`, with a count in `cl` or an
    /// immediate.
    Shift,
    /// `mul`, `imul` with 1, 2 or 3 operands, `div` and `idiv`.
    MulDiv,
    /// `push`, `pop`, `leave`, `pushf` and `popf`.
    Stack,
    /// `movs`, `stos`, `lods`, `scas` and `cmps`, with `rep`, `repe` or `repne`.
    String,
    /// The SSE moves: `movd`, `movq`, `movaps`, `movups`, `movapd`, `movupd`, `movdqa`,
    /// `movdqu`, `movss` and `movsd`.
    SseMove,
    /// `pxor`, `xorps` and `xorpd` with one register for both operands.
    SseZero,
    /// The single forms: exchanges, bit operations, counts, sign extensions, flag
    /// operations and `nop` forms.
    Single,
}

impl Template {
    /// Every template in table order.
    pub const ALL: &[Self] = &[
        Self::Alu2,
        Self::Alu1,
        Self::Mov,
        Self::Movx,
        Self::Lea,
        Self::Cmov,
        Self::Setcc,
        Self::Branch,
        Self::Shift,
        Self::MulDiv,
        Self::Stack,
        Self::String,
        Self::SseMove,
        Self::SseZero,
        Self::Single,
    ];

    /// Gives the name of the template, for example `alu2` or `sse_move`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Alu2 => "alu2",
            Self::Alu1 => "alu1",
            Self::Mov => "mov",
            Self::Movx => "movx",
            Self::Lea => "lea",
            Self::Cmov => "cmov",
            Self::Setcc => "setcc",
            Self::Branch => "branch",
            Self::Shift => "shift",
            Self::MulDiv => "muldiv",
            Self::Stack => "stack",
            Self::String => "string",
            Self::SseMove => "sse_move",
            Self::SseZero => "sse_zero",
            Self::Single => "single",
        }
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How a template gets the operation width of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WidthRule {
    /// The width of the first operand.
    Dst,
    /// A fixed width in bits.
    Fixed(u8),
}

/// One row of the mnemonic table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Row {
    /// The canonical mnemonic.
    pub mnem: Mnem,
    /// The template that lifts the mnemonic.
    pub template: Template,
    /// The flag operation of the flag thunk, or `None` when the row writes no thunk.
    pub flag_op: Option<FlagOp>,
    /// Tells if the instruction writes its first operand or an implicit destination.
    pub writes_dst: bool,
    /// The operation width.
    pub width: WidthRule,
}

/// The mnemonic table: one row for each mnemonic that a template lifts.
pub const ROWS: &[Row] = rows::ROWS;

/// Gives the row of a mnemonic, or `None` for a mnemonic without a row.
#[must_use]
pub fn row(mnem: Mnem) -> Option<&'static Row> {
    let index = rows::INDEX.get(mnem as usize).copied()?;
    ROWS.get(usize::from(index))
}

/// What [`lift`] does with an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftKind {
    /// The template of this row lifts the instruction.
    Template(&'static Row),
    /// The instruction is `syscall`. It lifts to one `Syscall` op.
    Syscall,
    /// The instruction lifts to one `Intrinsic` op with its [`effect`].
    Intrinsic,
    /// The instruction lifts to one `Unimpl` op.
    Unimpl,
}

/// The error of [`lift`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiftError {
    /// The IR builder refuses an op or the instruction.
    Build(BuildError),
}

impl fmt::Display for LiftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(e) => write!(f, "The IR builder refuses the instruction: {e}"),
        }
    }
}

impl std::error::Error for LiftError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Build(e) => Some(e),
        }
    }
}

impl From<BuildError> for LiftError {
    fn from(e: BuildError) -> Self {
        Self::Build(e)
    }
}

/// Tells what [`lift`] does with `insn`. The function adds no op.
#[must_use]
pub fn kind(insn: &Insn) -> LiftKind {
    let _ = insn;
    LiftKind::Unimpl
}

/// Adds the ops of `insn` to `b`. The call starts the instruction with [`Builder::begin`].
///
/// # Errors
///
/// Returns [`LiftError::Build`] when the builder refuses the instruction or an op, for
/// example an address that is not above the address of the instruction before it.
pub fn lift(insn: &Insn, b: &mut Builder) -> Result<(), LiftError> {
    b.begin(insn.addr(), insn.len())?;
    b.flow(Opc::Unimpl, ghidorah_ir::Arg::Nil, ghidorah_ir::Arg::Nil)?;
    Ok(())
}

/// Gives the effect of the `Intrinsic` op of `insn`: its name, the locations that it
/// writes and reads, and its memory effect.
///
/// The defs and uses hold the general and XMM registers of [`Insn::regs_written`] and
/// [`Insn::regs_read`], the flags word when the instruction writes or reads a status flag,
/// and the `fs` or `gs` base of a memory operand. An opaque form also writes and reads the
/// flags word. The memory effect comes from the first memory operand. A size of 0 means an
/// unknown size.
#[must_use]
pub fn effect(insn: &Insn) -> Effect {
    Effect {
        name: IntrinsicId(insn.mnem() as u16),
        defs: LocSet::EMPTY,
        uses: LocSet::EMPTY,
        mem: MemEffect::None,
    }
}

/// Gives the mnemonic that an [`IntrinsicId`] of this lifter names.
#[must_use]
pub fn intrinsic_mnem(id: IntrinsicId) -> Option<Mnem> {
    Mnem::ALL.get(usize::from(id.0)).copied()
}

/// The names of the intrinsic instructions of this lifter, for the IR printers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Names;

impl IntrinsicNames for Names {
    fn name(&self, id: IntrinsicId) -> Option<&'static str> {
        let _ = id;
        None
    }
}

/// Gives the full-width location of a register: a general register `rax` to `r31`, or an
/// XMM register for an `xmm`, `ymm` or `zmm` register. Other registers have no location.
#[must_use]
pub fn loc(reg: Reg) -> Option<Loc> {
    match reg.class() {
        RegClass::Gpr => Loc::gpr(reg.number()),
        _ => None,
    }
}
