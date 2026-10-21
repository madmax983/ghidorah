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
//!   `fs` or `gs` base. A RIP-relative operand gives a constant address, plus the `fs` or
//!   `gs` base with a segment override. A `rip` base never reads a register. `lea` adds no
//!   segment base.
//! - A `rep` string instruction is a loop on its own address. It stops when `rcx` is 0.
//! - The direction flag is 0, as the System V ABI requires at a call boundary. A
//!   [`BlockLift`] run keeps one more bit: `std` makes the direction unknown and `cld` makes
//!   it 0 again. While it is unknown, the `string` template does not fit, so a string
//!   instruction lifts to one `Intrinsic` op. The bit goes on through sequential
//!   instructions and conditional branches. A gap, a jump, a call, a return or a trap
//!   clears it.
//! - A quotient that does not fit in its register gives its low bits. The hardware raises
//!   a divide error there.
//! - An `Intrinsic` op of an instruction names the instruction by [`IntrinsicId`]: the
//!   code of its [`Mnem`] ([`intrinsic_mnem`] gives it back).

mod alu;
mod ctx;
mod data;
mod flow;
mod rows;
mod single;
mod sse;

use std::fmt;

use ghidorah_ir::{
    Arg, BuildError, Builder, Effect, EffectOperand, FlagOp, IntrinsicId, IntrinsicNames, Loc,
    LocSet, MAX_OPERANDS, MemEffect, Opc,
};

use crate::{Access, Flow, Insn, Mnem, Operand, Reg, RegClass, Seg};
use ctx::{Cx, Fail, Res, mem_ok, op_width, operands_ok};

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

/// Tells if a template supports the operands of an instruction. `dir_unknown` tells that a
/// `std` can be in effect.
fn fits(row: Row, insn: &Insn, dir_unknown: bool) -> bool {
    match row.template {
        Template::Lea => {
            matches!(insn.op(1), Some(Operand::Mem(m)) if mem_ok(&m))
                && operands_ok(insn, false)
                && op_width(insn.op(0).unwrap_or(Operand::Opaque)) >= 16
        }
        Template::Branch => {
            let wide = insn.ops().all(|op| match op {
                Operand::Reg { .. } | Operand::Mem(_) => op_width(op) == 64,
                _ => true,
            });
            let loop_ecx = matches!(row.mnem, Mnem::Loop | Mnem::Loope | Mnem::Loopne)
                && insn.prefixes().asz();
            wide && !loop_ecx && operands_ok(insn, false)
        }
        Template::Stack => {
            let short_leave = row.mnem == Mnem::Leave && insn.prefixes().osz();
            !short_leave && operands_ok(insn, false)
        }
        Template::String => flow::string_fits(insn, dir_unknown),
        Template::SseMove => sse::move_fits(insn),
        Template::SseZero => sse::zero_fits(insn),
        Template::Single => match row.mnem {
            Mnem::Bswap => matches!(insn.op(0).map(op_width), Some(32 | 64)),
            Mnem::Nop | Mnem::Endbr64 | Mnem::Pause | Mnem::Cld => true,
            _ => operands_ok(insn, false),
        },
        _ => operands_ok(insn, false),
    }
}

/// Tells what [`lift`] does with `insn`. The function adds no op.
#[must_use]
pub fn kind(insn: &Insn) -> LiftKind {
    kind_in(insn, false)
}

/// Tells what the lift does with `insn`. `dir_unknown` tells that a `std` can be in effect.
fn kind_in(insn: &Insn, dir_unknown: bool) -> LiftKind {
    if insn.mnem() == Mnem::Syscall {
        return LiftKind::Syscall;
    }
    match row(insn.mnem()) {
        Some(r) if fits(*r, insn, dir_unknown) => LiftKind::Template(r),
        _ if matches!(insn.flow(), Flow::Seq | Flow::Trap) => LiftKind::Intrinsic,
        _ => LiftKind::Unimpl,
    }
}

/// Runs the template of a row.
fn template(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    match row.template {
        Template::Alu2 => alu::alu2(cx, row),
        Template::Alu1 => alu::alu1(cx, row),
        Template::Mov => data::mov(cx),
        Template::Movx => data::movx(cx, row),
        Template::Lea => data::lea(cx),
        Template::Cmov => data::cmov(cx, row),
        Template::Setcc => data::setcc(cx, row),
        Template::Branch => flow::branch(cx, row),
        Template::Shift => alu::shift(cx, row),
        Template::MulDiv => alu::muldiv(cx, row),
        Template::Stack => data::stack(cx, row),
        Template::String => flow::string(cx, row),
        Template::SseMove => sse::sse_move(cx, row),
        Template::SseZero => sse::sse_zero(cx),
        Template::Single => single::single(cx, row),
    }
}

/// The effect of `syscall`: the call number and six arguments in, `rax`, `rcx` and `r11`
/// out.
fn syscall_effect() -> Effect {
    let defs = [Loc::RAX, Loc::RCX, Loc::R11].into_iter().collect();
    let uses = [
        Loc::RAX,
        Loc::RDI,
        Loc::RSI,
        Loc::RDX,
        Loc::R10,
        Loc::R8,
        Loc::R9,
    ]
    .into_iter()
    .collect();
    Effect {
        name: IntrinsicId(Mnem::Syscall as u16),
        defs,
        uses,
        mem: MemEffect::None,
        operands: [EffectOperand::None; MAX_OPERANDS],
    }
}

/// Adds the `Intrinsic` op of an instruction with the address of its memory operand.
fn intrinsic(cx: &mut Cx<'_>) -> Res<()> {
    let addr = match cx.insn.mem() {
        Some(m) if m.access != Access::Address && mem_ok(&m) => cx.addr(&m, true)?,
        _ => Arg::Nil,
    };
    Ok(cx.b.effect_op(Opc::Intrinsic, effect(cx.insn), addr)?)
}

/// Adds the ops of `insn` to `b`. The call starts the instruction with [`Builder::begin`].
///
/// # Errors
///
/// Returns [`LiftError::Build`] when the builder refuses the instruction or an op. An
/// example is an address that is not above the address of the instruction before it.
pub fn lift(insn: &Insn, b: &mut Builder) -> Result<(), LiftError> {
    lift_in(insn, b, false)
}

/// Adds the ops of `insn` to `b`. `dir_unknown` tells that a `std` can be in effect.
fn lift_in(insn: &Insn, b: &mut Builder, dir_unknown: bool) -> Result<(), LiftError> {
    b.begin(insn.addr(), insn.len())?;
    let mut cx = Cx { b, insn };
    let done = match kind_in(insn, dir_unknown) {
        LiftKind::Template(r) => template(&mut cx, *r),
        LiftKind::Syscall => Ok(cx.b.effect_op(Opc::Syscall, syscall_effect(), Arg::Nil)?),
        LiftKind::Intrinsic => intrinsic(&mut cx),
        LiftKind::Unimpl => Ok(cx.b.flow(Opc::Unimpl, Arg::Nil, Arg::Nil)?),
    };
    match done {
        Ok(()) => Ok(()),
        Err(Fail::Build(e)) => Err(LiftError::Build(e)),
        Err(Fail::Operand) => Ok(cx.b.flow(Opc::Unimpl, Arg::Nil, Arg::Nil)?),
    }
}

/// The lift context of a run of instructions: the direction flag rule of the module doc.
///
/// A caller lifts the instructions of a function in address order through one context. Each
/// instruction that does not follow the one before it starts a new block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockLift {
    /// The address after the last instruction, while its block goes on.
    next: Option<u64>,
    /// A `std` can be in effect at `next`.
    dir_unknown: bool,
}

impl BlockLift {
    /// Makes the context of a new block. The direction flag is 0 there.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: None,
            dir_unknown: false,
        }
    }

    /// Tells if a `std` can be in effect at `insn`.
    fn unknown_at(&self, insn: &Insn) -> bool {
        self.dir_unknown && self.next == Some(insn.addr())
    }

    /// Tells what [`BlockLift::lift`] does with `insn`. The function adds no op.
    #[must_use]
    pub fn kind(&self, insn: &Insn) -> LiftKind {
        kind_in(insn, self.unknown_at(insn))
    }

    /// Adds the ops of `insn` to `b` as [`lift`] does, and updates the context.
    ///
    /// # Errors
    ///
    /// Returns [`LiftError::Build`] when the builder refuses the instruction or an op, as
    /// [`lift`] does.
    pub fn lift(&mut self, insn: &Insn, b: &mut Builder) -> Result<(), LiftError> {
        let unknown = self.unknown_at(insn);
        let done = lift_in(insn, b, unknown);
        let goes_on = matches!(insn.flow(), Flow::Seq | Flow::Jcc);
        let after = match insn.mnem() {
            Mnem::Std => true,
            Mnem::Cld => false,
            _ => unknown,
        };
        self.dir_unknown = after && goes_on;
        self.next = goes_on.then(|| insn.next_addr());
        done
    }
}

/// Gives the effect of the `Intrinsic` op of `insn`: its name, the locations that it
/// writes and reads, and its memory effect.
///
/// The defs and uses hold the general and XMM registers of [`Insn::regs_written`] and
/// [`Insn::regs_read`]. They hold the flags word when the instruction writes or reads a
/// status flag. The uses hold the `fs` or `gs` base of a memory operand. An opaque form
/// also writes and reads the flags word, except `vzeroupper` and `vzeroall`. The memory
/// effect comes from the first memory operand. A size of 0 means an unknown size.
#[must_use]
pub fn effect(insn: &Insn) -> Effect {
    let mut defs: LocSet = insn.regs_written().iter().filter_map(loc).collect();
    let mut uses: LocSet = insn.regs_read().iter().filter_map(loc).collect();
    let opaque = insn.is_opaque() && crate::implicit::opaque_flags(insn);
    if opaque || !insn.flags_written().is_empty() {
        defs.insert(Loc::Flags);
    }
    if opaque || !insn.flags_read().is_empty() {
        uses.insert(Loc::Flags);
    }
    let mut mem = MemEffect::None;
    for op in insn.ops() {
        match op {
            Operand::Mem(m) => {
                if let Some(s) = m.seg.filter(|s| s.has_base()) {
                    uses.insert(if s == Seg::Fs {
                        Loc::FS_BASE
                    } else {
                        Loc::GS_BASE
                    });
                }
                let size = u32::from(m.width_bytes);
                let this = match m.access {
                    Access::Read => MemEffect::Read { size },
                    Access::Write => MemEffect::Write { size },
                    Access::ReadWrite => MemEffect::ReadWrite { size },
                    Access::Address => MemEffect::None,
                };
                if mem == MemEffect::None {
                    mem = this;
                }
            }
            Operand::Opaque if mem == MemEffect::None => mem = MemEffect::ReadWrite { size: 0 },
            _ => {}
        }
    }
    Effect {
        name: IntrinsicId(insn.mnem() as u16),
        defs,
        uses,
        mem,
        operands: operands(insn),
    }
}

/// Gives the explicit operands of `insn` in operand order: each register as its full-width
/// location, the memory operand and each immediate, masked to its width.
fn operands(insn: &Insn) -> [EffectOperand; MAX_OPERANDS] {
    let mut out = [EffectOperand::None; MAX_OPERANDS];
    let list = insn.ops().filter_map(|op| match op {
        Operand::Reg { reg, .. } => loc(reg).map(EffectOperand::Loc),
        Operand::Mem(_) => Some(EffectOperand::Mem),
        Operand::Imm { value, width, .. } => {
            let bits = u32::from(width).saturating_mul(8);
            let mask = u64::MAX
                .checked_shr(64u32.saturating_sub(bits))
                .unwrap_or(0);
            Some(EffectOperand::Imm(value.cast_unsigned() & mask))
        }
        Operand::Target { .. } | Operand::Opaque => None,
    });
    for (slot, op) in out.iter_mut().zip(list) {
        *slot = op;
    }
    out
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
        intrinsic_mnem(id).map(Mnem::name)
    }
}

/// Gives the full-width location of a register: a general register `rax` to `r31`, or an
/// XMM register for an `xmm`, `ymm` or `zmm` register. Other registers have no location.
#[must_use]
pub fn loc(reg: Reg) -> Option<Loc> {
    match reg.class() {
        RegClass::Gpr => Loc::gpr(reg.number()),
        RegClass::Xmm | RegClass::Ymm | RegClass::Zmm => Loc::xmm(reg.number()),
        _ => None,
    }
}
