//! The operand model of design Section 5.3.

use crate::regs::{Reg, Seg};

/// How an instruction uses an operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Access {
    /// The instruction reads the operand.
    #[default]
    Read = 0,
    /// The instruction writes the operand and does not read it.
    Write = 1,
    /// The instruction reads and writes the operand.
    ReadWrite = 2,
    /// The instruction uses only the address of a memory operand, as `lea` and `nop` do.
    Address = 3,
}

impl Access {
    /// Tells if the instruction reads the operand.
    #[must_use]
    pub const fn reads(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    /// Tells if the instruction writes the operand.
    #[must_use]
    pub const fn writes(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }

    pub(crate) const fn from_bits(bits: u8) -> Self {
        match bits & 3 {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::ReadWrite,
            _ => Self::Address,
        }
    }
}

/// A memory operand.
///
/// The address is `seg_base + base + index * scale + disp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mem {
    /// The segment. Only `fs` and `gs` have a base in the 64-bit mode. The string
    /// operands give `es` and `ds` explicitly.
    pub seg: Option<Seg>,
    /// The base register. A RIP-relative operand has [`Reg::RIP`] or [`Reg::EIP`].
    pub base: Option<Reg>,
    /// The index register.
    pub index: Option<Reg>,
    /// The scale of the index: 1, 2, 4 or 8.
    pub scale: u8,
    /// The displacement, sign-extended.
    pub disp: i64,
    /// The width of the access in bytes. Zero means an unknown width.
    pub width_bytes: u16,
    /// The address width in bits, 64 or 32.
    pub addr_width: u8,
    /// The absolute address: `next_ip + disp` for a RIP-relative operand, or the
    /// displacement for an operand without base and index. `None` with `fs` or `gs`.
    pub abs_target: Option<u64>,
    /// How the instruction uses the memory.
    pub access: Access,
}

impl Mem {
    /// Tells if the base is the instruction pointer.
    #[must_use]
    pub fn is_rip_relative(&self) -> bool {
        self.base == Some(Reg::RIP) || self.base == Some(Reg::EIP)
    }
}

/// An operand of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operand {
    /// A register.
    Reg {
        /// The register.
        reg: Reg,
        /// How the instruction uses it.
        access: Access,
    },
    /// An immediate value.
    Imm {
        /// The value. It is sign-extended when `signed` is `true`.
        value: i64,
        /// The width of the operand in bytes, after any extension.
        width: u8,
        /// Tells if the encoding sign-extends a smaller immediate.
        signed: bool,
    },
    /// A memory operand.
    Mem(Mem),
    /// The target of a direct branch or call.
    Target {
        /// The absolute target address.
        addr: u64,
    },
    /// An operand of an opaque form whose details the decoder does not know.
    Opaque,
}
