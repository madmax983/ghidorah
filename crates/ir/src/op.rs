//! L0 ops (design Section 6.1, ADR-0009).
//!
//! An [`Op`] has an [`OpId`], an opcode, a width in bits, an aux byte, an optional output
//! value and three arguments. A value ([`Val`]) has one def. An argument is a value, a
//! constant, a location or nothing.
//!
//! The width `w` and the aux byte `sub` give every width of an op. So an op never needs
//! the width of the op that defines its input. The table gives the rules.
//!
//! | Opcodes | `w` | `sub` | Arguments | Output |
//! |---|---|---|---|---|
//! | `Get` | location width | - | `L(loc)` | `w` bits |
//! | `Put` | location width | - | `L(loc)`, value | - |
//! | `Copy`, `Neg`, `Not`, `Popcnt`, `Clz`, `Ctz`, `Bswap` | operand width | - | `x` | `w` bits |
//! | `Add` to `Xor`, `UMulHi`, `SMulHi`, divisions | operand width | - | `x`, `y` | `w` bits |
//! | `Shl`, `LShr`, `AShr`, `Rol`, `Ror` | operand width | - | `x`, count | `w` bits |
//! | `Eq` to `TestNZ` | operand width | - | `x`, `y` | 1 bit |
//! | `Load` | access width | - | address | `w` bits |
//! | `Store` | access width | - | address, value | - |
//! | `ZExt`, `SExt` | output width | input width | `x` | `w` bits |
//! | `Trunc` | output width | - | `x` | `w` bits |
//! | `Extract` | output width | - | `x`, `K(low bit)` | `w` bits |
//! | `Insert` | base width | part width | base, part, `K(low bit)` | `w` bits |
//! | `Ite` | operand width | - | condition, `t`, `f` | `w` bits |
//! | `Flags` | operand width | [`FlagOp`] code | `a`, `b`, `c` | flags word |
//! | `Cond` | 1 | [`Cc`] code | flags | 1 bit |
//! | `FlagsSel` | 16 | - | condition, `f1`, `f2` | flags word |
//! | `FlagsGet` | output width | - | flags | `w` bits |
//! | `FlagsSet` | 16 | - | value | flags word |
//! | `Jump`, `JumpInd`, `Call`, `CallInd` | 64 | - | target | - |
//! | `CJump` | 64 | - | condition, target | - |
//! | `Syscall` | 64 | - | `K(effect index)` | - |
//! | `Intrinsic` | 64 | - | `K(effect index)`, memory address or `Nil` | - |
//! | `Ret`, `Unimpl`, `Nop` | 0 | - | - | - |
//! | `Phi` (L1 only) | value width | - | `K(phi list index)` | `w` bits |
//!
//! Argument `c` of `Flags` is the carry-in of `Adc` and `Sbb`. For `Inc`, `Dec`, `Bt`,
//! shifts and rotates, `c` is the old flags word.

use std::fmt;

pub use ghidorah_base::OpId;

use crate::loc::{Loc, LocSet};

/// A value: the output of one op. Each value has exactly one def.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Val(pub u32);

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// A 64-bit constant in two 32-bit halves.
///
/// The halves keep the alignment of [`Arg`] at 4 bytes, so an [`Op`] fits in 64 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Imm {
    hi: u32,
    lo: u32,
}

impl Imm {
    /// Makes a constant.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "each half keeps 32 bits of the value on purpose"
        )]
        Self {
            hi: (value >> 32) as u32,
            lo: value as u32,
        }
    }

    /// Gives the value of the constant.
    #[must_use]
    pub const fn get(self) -> u64 {
        ((self.hi as u64) << 32) | self.lo as u64
    }
}

/// An argument of an op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Arg {
    /// No argument.
    #[default]
    Nil,
    /// A value.
    V(Val),
    /// A constant.
    K(Imm),
    /// A location. Only `Get` and `Put` take one.
    L(Loc),
}

impl Arg {
    /// Makes a constant argument.
    #[must_use]
    pub const fn k(value: u64) -> Self {
        Self::K(Imm::new(value))
    }

    /// Gives the constant, or `None` for another kind.
    #[must_use]
    pub const fn as_k(self) -> Option<u64> {
        match self {
            Self::K(imm) => Some(imm.get()),
            _ => None,
        }
    }

    /// Gives the value, or `None` for another kind.
    #[must_use]
    pub const fn as_v(self) -> Option<Val> {
        match self {
            Self::V(v) => Some(v),
            _ => None,
        }
    }

    /// Gives the location, or `None` for another kind.
    #[must_use]
    pub const fn as_loc(self) -> Option<Loc> {
        match self {
            Self::L(loc) => Some(loc),
            _ => None,
        }
    }
}

impl From<Val> for Arg {
    fn from(v: Val) -> Self {
        Self::V(v)
    }
}

impl fmt::Display for Arg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => f.write_str("_"),
            Self::V(v) => write!(f, "{v}"),
            Self::K(imm) => write!(f, "{:#x}", imm.get()),
            Self::L(loc) => write!(f, "{loc}"),
        }
    }
}

/// Declares [`Opc`] with its names in one list.
macro_rules! opcodes {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        /// An L0 or L1 opcode. The module table gives the width rules.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum Opc {
            $($(#[$doc])* $name,)*
        }

        impl Opc {
            /// Every opcode in code order.
            pub const ALL: &[Self] = &[$(Self::$name,)*];

            /// Gives the name of the opcode, for example `Add`.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$name => stringify!($name),)*
                }
            }
        }
    };
}

opcodes! {
    /// Read a location.
    Get,
    /// Write a location.
    Put,
    /// Copy a value.
    Copy,
    /// Read memory.
    Load,
    /// Write memory.
    Store,
    /// Wrapping addition.
    Add,
    /// Wrapping subtraction.
    Sub,
    /// The low half of a product.
    Mul,
    /// The high half of an unsigned product.
    UMulHi,
    /// The high half of a signed product.
    SMulHi,
    /// Unsigned division. A zero divisor stops the interpreter.
    UDiv,
    /// Signed division, rounded to zero. The minimum value divided by -1 gives the minimum.
    SDiv,
    /// Unsigned remainder.
    URem,
    /// Signed remainder with the sign of the dividend.
    SRem,
    /// Two's complement negation.
    Neg,
    /// Bitwise not.
    Not,
    /// Bitwise and.
    And,
    /// Bitwise or.
    Or,
    /// Bitwise exclusive or.
    Xor,
    /// Shift left. A count of `w` or more gives 0.
    Shl,
    /// Logical shift right. A count of `w` or more gives 0.
    LShr,
    /// Arithmetic shift right. A count of `w` or more gives the sign in each bit.
    AShr,
    /// Rotate left by the count modulo `w`.
    Rol,
    /// Rotate right by the count modulo `w`.
    Ror,
    /// Zero extension from `sub` bits.
    ZExt,
    /// Sign extension from `sub` bits.
    SExt,
    /// The low `w` bits.
    Trunc,
    /// `w` bits from a low bit.
    Extract,
    /// A part of `sub` bits put into a base at a low bit.
    Insert,
    /// The count of 1 bits.
    Popcnt,
    /// The count of leading 0 bits. A zero input gives `w`.
    Clz,
    /// The count of trailing 0 bits. A zero input gives `w`.
    Ctz,
    /// The bytes in reverse order.
    Bswap,
    /// `x == y`.
    Eq,
    /// `x != y`.
    Ne,
    /// Unsigned `x < y`.
    ULt,
    /// Unsigned `x <= y`.
    ULe,
    /// Signed `x < y`.
    SLt,
    /// Signed `x <= y`.
    SLe,
    /// `x & y == 0`.
    TestZ,
    /// `x & y != 0`.
    TestNZ,
    /// `t` when the condition is not 0, else `f`.
    Ite,
    /// The lazy flag thunk of a [`FlagOp`].
    Flags,
    /// An x86 condition on a flags word.
    Cond,
    /// `f1` when the condition is not 0, else `f2`.
    FlagsSel,
    /// A value from a flags word (`pushf`, `lahf`).
    FlagsGet,
    /// A flags word from a value (`popf`, `sahf`).
    FlagsSet,
    /// A jump to a target.
    Jump,
    /// A jump to a target when the condition is not 0.
    CJump,
    /// A jump to a computed target.
    JumpInd,
    /// A call of a target.
    Call,
    /// A call of a computed target.
    CallInd,
    /// A return.
    Ret,
    /// A system call with the def and use sets of its effect.
    Syscall,
    /// An instruction that the lifter keeps opaque, with its effect.
    Intrinsic,
    /// A decoded instruction that the lifter does not handle.
    Unimpl,
    /// No operation.
    Nop,
    /// An SSA phi (L1 only).
    Phi,
}

impl Opc {
    /// Gives the opcode of a code, or `None` for a code without an opcode.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
    }

    /// Tells if the op gives a 1-bit compare result.
    #[must_use]
    pub const fn is_compare(self) -> bool {
        matches!(
            self,
            Self::Eq
                | Self::Ne
                | Self::ULt
                | Self::ULe
                | Self::SLt
                | Self::SLe
                | Self::TestZ
                | Self::TestNZ
        )
    }

    /// Tells if the op can change the flow of control.
    #[must_use]
    pub const fn is_flow(self) -> bool {
        matches!(
            self,
            Self::Jump
                | Self::CJump
                | Self::JumpInd
                | Self::Call
                | Self::CallInd
                | Self::Ret
                | Self::Syscall
                | Self::Intrinsic
                | Self::Unimpl
        )
    }

    /// Tells if the op has an output value.
    #[must_use]
    pub const fn has_out(self) -> bool {
        !matches!(
            self,
            Self::Put
                | Self::Store
                | Self::Jump
                | Self::CJump
                | Self::JumpInd
                | Self::Call
                | Self::CallInd
                | Self::Ret
                | Self::Syscall
                | Self::Intrinsic
                | Self::Unimpl
                | Self::Nop
        )
    }
}

impl fmt::Display for Opc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The operation of a flag thunk (design Section 6.2).
///
/// `sem::x86_flags` gives the flags of each operation. The `A64*` names are reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FlagOp {
    /// `a + b`.
    X86Add,
    /// `a - b`.
    X86Sub,
    /// `a + b + (c & 1)`.
    X86Adc,
    /// `a - b - (c & 1)`.
    X86Sbb,
    /// `a & b`. The lifter gives `r, r` for `or` and `xor` with the result `r`.
    X86Logic,
    /// `a + 1`. CF comes from the old flags `c`.
    X86Inc,
    /// `a - 1`. CF comes from the old flags `c`.
    X86Dec,
    /// `0 - a`.
    X86Neg,
    /// `a << b`. A count of 0 keeps the old flags `c`.
    X86Shl,
    /// `a >> b` (logical). A count of 0 keeps the old flags `c`.
    X86Shr,
    /// `a >> b` (arithmetic). A count of 0 keeps the old flags `c`.
    X86Sar,
    /// `a` rotated left by `b`. Only CF and OF change.
    X86Rol,
    /// `a` rotated right by `b`. Only CF and OF change.
    X86Ror,
    /// The unsigned product `a * b`. CF and OF tell if the high half is not 0.
    X86UMul,
    /// The signed product `a * b`. CF and OF tell if the product does not fit in `w` bits.
    X86SMul,
    /// Bit `b` of `a` goes to CF. ZF comes from the old flags `c`.
    X86Bt,
    /// The status bits of `a`.
    Copy,
}

impl FlagOp {
    /// Every flag operation in code order.
    pub const ALL: &[Self] = &[
        Self::X86Add,
        Self::X86Sub,
        Self::X86Adc,
        Self::X86Sbb,
        Self::X86Logic,
        Self::X86Inc,
        Self::X86Dec,
        Self::X86Neg,
        Self::X86Shl,
        Self::X86Shr,
        Self::X86Sar,
        Self::X86Rol,
        Self::X86Ror,
        Self::X86UMul,
        Self::X86SMul,
        Self::X86Bt,
        Self::Copy,
    ];

    /// Gives the flag operation of a code, or `None` for a code without an operation.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
    }

    /// Gives the code of the flag operation.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// The names of the x86 conditions in Jcc low-nibble order.
const CC_NAMES: [&str; 16] = [
    "o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g",
];

/// A condition code. `X86` holds the low nibble of the Jcc opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cc {
    /// An x86 condition, 0 to 15.
    X86(u8),
}

impl Cc {
    /// Gives the x86 condition `n`, or `None` when `n` is 16 or more.
    #[must_use]
    pub const fn x86(n: u8) -> Option<Self> {
        if n < 16 { Some(Self::X86(n)) } else { None }
    }

    /// Gives the code of the condition: the low nibble of the Jcc opcode.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::X86(n) => n & 0xf,
        }
    }

    /// Gives the name of the condition, for example `ne`.
    #[must_use]
    pub fn name(self) -> &'static str {
        CC_NAMES
            .get(usize::from(self.code()))
            .copied()
            .unwrap_or("?")
    }
}

/// The name of an opaque instruction. The ISA crate gives the meaning of the number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntrinsicId(pub u16);

/// The memory effect of an opaque instruction. The address is argument 1 of the op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemEffect {
    /// The op does not touch memory.
    None,
    /// The op reads `size` bytes.
    Read {
        /// The count of bytes.
        size: u32,
    },
    /// The op writes `size` bytes.
    Write {
        /// The count of bytes.
        size: u32,
    },
    /// The op reads and writes `size` bytes.
    ReadWrite {
        /// The count of bytes.
        size: u32,
    },
}

/// The largest count of explicit operands of an opaque instruction.
pub const MAX_OPERANDS: usize = 4;

/// One explicit operand of an opaque instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum EffectOperand {
    /// No operand.
    #[default]
    None,
    /// A register, as its full-width location.
    Loc(Loc),
    /// The memory operand. Its address is argument 1 of the op.
    Mem,
    /// An immediate.
    Imm(u64),
}

/// The effect of a `Syscall` or `Intrinsic` op: its name, defs, uses and memory effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Effect {
    /// The name of the instruction.
    pub name: IntrinsicId,
    /// The locations that the op writes.
    pub defs: LocSet,
    /// The locations that the op reads.
    pub uses: LocSet,
    /// The memory effect.
    pub mem: MemEffect,
    /// The explicit operands in the operand order of the instruction, the destination first.
    /// The uses keep no order, so a printer reads the order and the immediates here.
    pub operands: [EffectOperand; MAX_OPERANDS],
}

/// One L0 or L1 op. It has at most 64 bytes (AC-067).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Op {
    /// The instruction address and the sequence number.
    pub id: OpId,
    /// The opcode.
    pub opc: Opc,
    /// The width in bits, at most 128. The module table gives its meaning for each opcode.
    pub w: u8,
    /// The aux byte: a [`FlagOp`] code, a [`Cc`] code or an input width.
    pub sub: u8,
    /// The output value.
    pub out: Option<Val>,
    /// The arguments.
    pub a: [Arg; 3],
}

impl Op {
    /// Gives the flag operation of a `Flags` op, or `None`.
    #[must_use]
    pub fn flag_op(&self) -> Option<FlagOp> {
        match self.opc {
            Opc::Flags => FlagOp::from_code(self.sub),
            _ => None,
        }
    }

    /// Gives the condition of a `Cond` op, or `None`.
    #[must_use]
    pub const fn cc(&self) -> Option<Cc> {
        match self.opc {
            Opc::Cond => Cc::x86(self.sub),
            _ => None,
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(out) = self.out {
            write!(f, "{out} = ")?;
        }
        write!(f, "{}.{}", self.opc, self.w)?;
        match (self.flag_op(), self.cc()) {
            (Some(op), _) => write!(f, " {op:?}")?,
            (None, Some(cc)) => write!(f, " {}", cc.name())?,
            (None, None) if self.sub != 0 => write!(f, " #{}", self.sub)?,
            (None, None) => {}
        }
        for arg in self.a.iter().filter(|a| **a != Arg::Nil) {
            write!(f, " {arg}")?;
        }
        Ok(())
    }
}
