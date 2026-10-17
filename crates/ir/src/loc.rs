//! Locations of the machine state (design Section 6.1).
//!
//! A [`Loc`] is a register, the flags word or a stack slot. `Get` and `Put` are the only
//! ops that read or write a location. Registers are full width: a general register has
//! 64 bits, and an XMM register has 128 bits.
//!
//! | Register numbers | Registers |
//! |---|---|
//! | 0 to 31 | `rax`, `rcx`, `rdx`, `rbx`, `rsp`, `rbp`, `rsi`, `rdi`, `r8` to `r31` |
//! | 32 to 63 | `xmm0` to `xmm31` |
//! | 64, 65 | `fs_base`, `gs_base` |

use std::fmt;

/// The count of general registers, `r16` to `r31` (APX) included.
pub const GPR_COUNT: u16 = 32;

/// The number of the first XMM register.
pub const XMM_BASE: u16 = 32;

/// The count of XMM registers.
pub const XMM_COUNT: u16 = 32;

/// The count of register numbers that have a name.
pub const REG_COUNT: u16 = 66;

/// The names of the first 16 general registers, in encoding order.
const GPR_NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// A location of the machine state.
///
/// The order is `Reg`, then `Flags`, then `Stack`. Inside a kind, the number gives the order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Loc {
    /// A register by its number (see the module table).
    Reg(u16),
    /// The flags word. Bit 0 is CF, bit 2 is PF, bit 4 is AF, bit 6 is ZF, bit 7 is SF
    /// and bit 11 is OF.
    Flags,
    /// The stack slot at this offset from the stack pointer at function entry.
    Stack(i32),
}

impl Loc {
    /// The register `rax`.
    pub const RAX: Self = Self::Reg(0);
    /// The register `rcx`.
    pub const RCX: Self = Self::Reg(1);
    /// The register `rdx`.
    pub const RDX: Self = Self::Reg(2);
    /// The register `rbx`.
    pub const RBX: Self = Self::Reg(3);
    /// The register `rsp`.
    pub const RSP: Self = Self::Reg(4);
    /// The register `rbp`.
    pub const RBP: Self = Self::Reg(5);
    /// The register `rsi`.
    pub const RSI: Self = Self::Reg(6);
    /// The register `rdi`.
    pub const RDI: Self = Self::Reg(7);
    /// The register `r8`.
    pub const R8: Self = Self::Reg(8);
    /// The register `r9`.
    pub const R9: Self = Self::Reg(9);
    /// The register `r10`.
    pub const R10: Self = Self::Reg(10);
    /// The register `r11`.
    pub const R11: Self = Self::Reg(11);
    /// The base address of the `fs` segment.
    pub const FS_BASE: Self = Self::Reg(64);
    /// The base address of the `gs` segment.
    pub const GS_BASE: Self = Self::Reg(65);

    /// Gives the general register `n`, or `None` when `n` is 32 or more.
    #[must_use]
    pub const fn gpr(n: u8) -> Option<Self> {
        if (n as u16) < GPR_COUNT {
            Some(Self::Reg(n as u16))
        } else {
            None
        }
    }

    /// Gives the XMM register `n`, or `None` when `n` is 32 or more.
    #[must_use]
    pub const fn xmm(n: u8) -> Option<Self> {
        if (n as u16) < XMM_COUNT {
            Some(Self::Reg(XMM_BASE + n as u16))
        } else {
            None
        }
    }

    /// Tells if the location is a general register.
    #[must_use]
    pub const fn is_gpr(self) -> bool {
        matches!(self, Self::Reg(n) if n < GPR_COUNT)
    }

    /// Tells if the location is an XMM register.
    #[must_use]
    pub const fn is_xmm(self) -> bool {
        matches!(self, Self::Reg(n) if n >= XMM_BASE && n < XMM_BASE + XMM_COUNT)
    }

    /// Gives the width of the location in bits.
    ///
    /// An XMM register has 128 bits and the flags word has 16 bits.
    /// Each other location has 64 bits.
    #[must_use]
    pub const fn width(self) -> u8 {
        match self {
            Self::Flags => 16,
            _ if self.is_xmm() => 128,
            _ => 64,
        }
    }
}

impl fmt::Display for Loc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Reg(n) if n < 16 => {
                f.write_str(GPR_NAMES.get(usize::from(n)).copied().unwrap_or("reg"))
            }
            Self::Reg(n) if n < GPR_COUNT => write!(f, "r{n}"),
            Self::Reg(n) if n < XMM_BASE + XMM_COUNT => write!(f, "xmm{}", n - XMM_BASE),
            Self::Reg(64) => f.write_str("fs_base"),
            Self::Reg(65) => f.write_str("gs_base"),
            Self::Reg(n) => write!(f, "reg{n}"),
            Self::Flags => f.write_str("flags"),
            Self::Stack(k) if k < 0 => write!(f, "stack-{:#x}", k.unsigned_abs()),
            Self::Stack(k) => write!(f, "stack+{k:#x}"),
        }
    }
}

/// A set of registers and the flags word.
///
/// The set holds registers 0 to 127. It cannot hold a stack slot.
/// Iteration gives the locations in [`Loc`] order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct LocSet {
    regs: u128,
    flags: bool,
}

impl LocSet {
    /// The empty set.
    pub const EMPTY: Self = Self {
        regs: 0,
        flags: false,
    };

    /// Gives the set with `loc` added, or `None` when the set cannot hold `loc`.
    #[must_use]
    pub const fn with(self, loc: Loc) -> Option<Self> {
        match loc {
            Loc::Reg(n) if n < 128 => Some(Self {
                regs: self.regs | (1u128 << n),
                flags: self.flags,
            }),
            Loc::Flags => Some(Self {
                regs: self.regs,
                flags: true,
            }),
            Loc::Reg(_) | Loc::Stack(_) => None,
        }
    }

    /// Adds `loc`. Gives `false` when the set cannot hold `loc`.
    pub fn insert(&mut self, loc: Loc) -> bool {
        match self.with(loc) {
            Some(set) => {
                *self = set;
                true
            }
            None => false,
        }
    }

    /// Tells if the set holds `loc`.
    #[must_use]
    pub const fn contains(&self, loc: Loc) -> bool {
        match loc {
            Loc::Reg(n) if n < 128 => self.regs & (1u128 << n) != 0,
            Loc::Flags => self.flags,
            Loc::Reg(_) | Loc::Stack(_) => false,
        }
    }

    /// Gives the union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            regs: self.regs | other.regs,
            flags: self.flags || other.flags,
        }
    }

    /// Tells if the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.regs == 0 && !self.flags
    }

    /// Gives the count of locations in the set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.regs.count_ones() as usize + if self.flags { 1 } else { 0 }
    }

    /// Gives the locations of the set in [`Loc`] order.
    pub fn iter(&self) -> impl Iterator<Item = Loc> + '_ {
        (0u16..128)
            .filter(|&n| self.regs & (1u128 << n) != 0)
            .map(Loc::Reg)
            .chain(self.flags.then_some(Loc::Flags))
    }
}

impl FromIterator<Loc> for LocSet {
    /// Makes a set of the locations that it can hold. It skips the others.
    fn from_iter<T: IntoIterator<Item = Loc>>(iter: T) -> Self {
        let mut set = Self::EMPTY;
        for loc in iter {
            let _added = set.insert(loc);
        }
        set
    }
}
