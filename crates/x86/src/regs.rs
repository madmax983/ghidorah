//! The register model of design Section 5.3.
//!
//! A [`Reg`] packs four fields into 13 bits of a `u16`:
//!
//! | Bits | Field |
//! |---|---|
//! | 0 to 4 | number, 0 to 31 |
//! | 5 | high byte (`ah`, `ch`, `dh`, `bh`) |
//! | 6 to 8 | width code: 8, 16, 32, 64, 80, 128, 256 or 512 bits |
//! | 9 to 12 | class |
//!
//! With any REX prefix, the byte registers 4 to 7 are `spl`, `bpl`, `sil` and `dil`.
//! Without a REX prefix they are `ah`, `ch`, `dh` and `bh`.

use std::fmt;

use crate::tables::regnames;

/// The class of a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RegClass {
    /// A general-purpose register, `rax` to `r31`.
    Gpr = 0,
    /// A 128-bit vector register, `xmm0` to `xmm31`.
    Xmm = 1,
    /// A 256-bit vector register.
    Ymm = 2,
    /// A 512-bit vector register.
    Zmm = 3,
    /// A segment register.
    Seg = 4,
    /// An MMX register, `mm0` to `mm7`.
    Mmx = 5,
    /// An x87 stack register, `st(0)` to `st(7)`.
    X87 = 6,
    /// A control register, `cr0` to `cr15`.
    Ctrl = 7,
    /// A debug register, `dr0` to `dr15`.
    Debug = 8,
    /// The instruction pointer, `rip` or `eip`.
    Ip = 9,
    /// An AVX-512 mask register, `k0` to `k7`.
    Mask = 10,
    /// An MPX bound register, `bnd0` to `bnd3`.
    Bnd = 11,
}

impl RegClass {
    const ALL: [Self; 12] = [
        Self::Gpr,
        Self::Xmm,
        Self::Ymm,
        Self::Zmm,
        Self::Seg,
        Self::Mmx,
        Self::X87,
        Self::Ctrl,
        Self::Debug,
        Self::Ip,
        Self::Mask,
        Self::Bnd,
    ];
}

/// A segment register in the order of the ModRM `reg` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Seg {
    /// `es`
    Es = 0,
    /// `cs`
    Cs = 1,
    /// `ss`
    Ss = 2,
    /// `ds`
    Ds = 3,
    /// `fs`
    Fs = 4,
    /// `gs`
    Gs = 5,
}

impl Seg {
    /// Gives the segment of a ModRM `reg` value, 0 to 5.
    #[must_use]
    pub const fn from_number(n: u8) -> Option<Self> {
        match n {
            0 => Some(Self::Es),
            1 => Some(Self::Cs),
            2 => Some(Self::Ss),
            3 => Some(Self::Ds),
            4 => Some(Self::Fs),
            5 => Some(Self::Gs),
            _ => None,
        }
    }

    /// Gives the name, for example `fs`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Es => "es",
            Self::Cs => "cs",
            Self::Ss => "ss",
            Self::Ds => "ds",
            Self::Fs => "fs",
            Self::Gs => "gs",
        }
    }

    /// Tells if the 64-bit mode uses the segment base. Only `fs` and `gs` have a base.
    #[must_use]
    pub const fn has_base(self) -> bool {
        matches!(self, Self::Fs | Self::Gs)
    }

    /// Gives the 16-bit segment register.
    #[must_use]
    pub const fn reg(self) -> Reg {
        Reg::pack(RegClass::Seg, self as u8, 1, false)
    }
}

/// A register (design Section 5.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reg(u16);

/// The width in bits of each width code.
const WIDTHS: [u16; 8] = [8, 16, 32, 64, 80, 128, 256, 512];

impl Reg {
    /// `rax`
    pub const RAX: Self = Self::gpr(0, 64);
    /// `rcx`
    pub const RCX: Self = Self::gpr(1, 64);
    /// `rdx`
    pub const RDX: Self = Self::gpr(2, 64);
    /// `rbx`
    pub const RBX: Self = Self::gpr(3, 64);
    /// `rsp`
    pub const RSP: Self = Self::gpr(4, 64);
    /// `rbp`
    pub const RBP: Self = Self::gpr(5, 64);
    /// `rsi`
    pub const RSI: Self = Self::gpr(6, 64);
    /// `rdi`
    pub const RDI: Self = Self::gpr(7, 64);
    /// `r8`
    pub const R8: Self = Self::gpr(8, 64);
    /// `r9`
    pub const R9: Self = Self::gpr(9, 64);
    /// `r10`
    pub const R10: Self = Self::gpr(10, 64);
    /// `r11`
    pub const R11: Self = Self::gpr(11, 64);
    /// `rip`
    pub const RIP: Self = Self::pack(RegClass::Ip, 0, 3, false);
    /// `eip`
    pub const EIP: Self = Self::pack(RegClass::Ip, 0, 2, false);
    /// `st(0)`, the top of the x87 stack
    pub const ST0: Self = Self::st(0);

    const fn pack(class: RegClass, number: u8, width_code: u8, high: bool) -> Self {
        let n = (number & 0x1f) as u16;
        let w = ((width_code & 7) as u16) << 6;
        let h = if high { 1 << 5 } else { 0 };
        Self(((class as u16) << 9) | w | h | n)
    }

    const fn width_code(bits: u16) -> u8 {
        match bits {
            8 => 0,
            16 => 1,
            32 => 2,
            80 => 4,
            128 => 5,
            256 => 6,
            512 => 7,
            _ => 3,
        }
    }

    /// Makes a general-purpose register. `width_bits` is 8, 16, 32 or 64.
    ///
    /// The number uses its low 5 bits. A byte register with the number 4 to 7 is
    /// `spl`, `bpl`, `sil` or `dil`. Use [`Reg::high_byte`] for `ah` to `bh`.
    #[must_use]
    pub const fn gpr(number: u8, width_bits: u16) -> Self {
        Self::pack(RegClass::Gpr, number, Self::width_code(width_bits), false)
    }

    /// Makes `ah`, `ch`, `dh` or `bh` from the number of `rax`, `rcx`, `rdx` or `rbx` (0 to 3).
    #[must_use]
    pub const fn high_byte(number: u8) -> Self {
        Self::pack(RegClass::Gpr, number & 3, 0, true)
    }

    /// Makes `xmm<n>`.
    #[must_use]
    pub const fn xmm(number: u8) -> Self {
        Self::pack(RegClass::Xmm, number, 5, false)
    }

    /// Makes `ymm<n>`.
    #[must_use]
    pub const fn ymm(number: u8) -> Self {
        Self::pack(RegClass::Ymm, number, 6, false)
    }

    /// Makes `zmm<n>`.
    #[must_use]
    pub const fn zmm(number: u8) -> Self {
        Self::pack(RegClass::Zmm, number, 7, false)
    }

    /// Makes `mm<n>`. The number uses its low 3 bits.
    #[must_use]
    pub const fn mmx(number: u8) -> Self {
        Self::pack(RegClass::Mmx, number & 7, 3, false)
    }

    /// Makes `st(<n>)`. The number uses its low 3 bits.
    #[must_use]
    pub const fn st(number: u8) -> Self {
        Self::pack(RegClass::X87, number & 7, 4, false)
    }

    /// Makes `cr<n>`. The number uses its low 4 bits.
    #[must_use]
    pub const fn cr(number: u8) -> Self {
        Self::pack(RegClass::Ctrl, number & 15, 3, false)
    }

    /// Makes `dr<n>`. The number uses its low 4 bits.
    #[must_use]
    pub const fn dr(number: u8) -> Self {
        Self::pack(RegClass::Debug, number & 15, 3, false)
    }

    /// Gives the packed bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Unpacks a register. Bits outside the 13 fields, or an unknown class, give `None`.
    #[must_use]
    pub fn from_bits(bits: u16) -> Option<Self> {
        let class = usize::from(bits >> 9);
        if class >= RegClass::ALL.len() {
            return None;
        }
        Some(Self(bits))
    }

    /// Gives the class.
    #[must_use]
    pub fn class(self) -> RegClass {
        RegClass::ALL
            .get(usize::from(self.0 >> 9))
            .copied()
            .unwrap_or(RegClass::Gpr)
    }

    /// Gives the number, 0 to 31.
    #[must_use]
    pub const fn number(self) -> u8 {
        (self.0 & 0x1f) as u8
    }

    /// Gives the width in bits.
    #[must_use]
    pub fn width_bits(self) -> u16 {
        WIDTHS
            .get(usize::from((self.0 >> 6) & 7))
            .copied()
            .unwrap_or(64)
    }

    /// Gives the width in bytes. An 80-bit register gives 10.
    #[must_use]
    pub fn width_bytes(self) -> u16 {
        self.width_bits() / 8
    }

    /// Tells if the register is `ah`, `ch`, `dh` or `bh`.
    #[must_use]
    pub const fn is_high_byte(self) -> bool {
        self.0 & (1 << 5) != 0
    }

    /// Gives the full register that holds this register.
    ///
    /// A general-purpose register gives the 64-bit register of the same number.
    /// `ah` gives `rax`. A vector register gives the `xmm` register of the same number.
    /// Other registers give themselves.
    #[must_use]
    pub fn full(self) -> Self {
        match self.class() {
            RegClass::Gpr => Self::gpr(self.number(), 64),
            RegClass::Xmm | RegClass::Ymm | RegClass::Zmm => Self::xmm(self.number()),
            RegClass::Ip => Self::RIP,
            _ => self,
        }
    }

    /// Gives the bit range `(low, high)` of the register inside [`Reg::full`].
    ///
    /// `ah` gives `(8, 16)`. `eax` gives `(0, 32)`.
    #[must_use]
    pub fn bit_range(self) -> (u16, u16) {
        if self.is_high_byte() {
            (8, 16)
        } else {
            (0, self.width_bits())
        }
    }

    /// Tells if a write to the register sets the bits above it in [`Reg::full`] to zero.
    ///
    /// Only a 32-bit general-purpose register does this.
    #[must_use]
    pub fn write_zero_extends(self) -> bool {
        self.class() == RegClass::Gpr && self.width_bits() == 32
    }

    /// Gives the name, for example `eax`, `spl`, `xmm1` or `st(2)`.
    #[must_use]
    pub fn name(self) -> &'static str {
        regnames::name(self.class(), self.number(), self.width_bits(), self.is_high_byte())
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Debug for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reg({})", self.name())
    }
}

/// A set of full registers.
///
/// | Bits | Registers |
/// |---|---|
/// | 0 to 31 | general-purpose registers |
/// | 32 to 63 | vector registers (`xmm`, `ymm` and `zmm` share a bit) |
/// | 64 to 69 | segment registers |
/// | 70 | the instruction pointer |
/// | 72 to 79 | MMX registers |
/// | 80 to 87 | x87 stack registers |
/// | 88 to 95 | mask registers |
/// | 96 to 111 | control registers |
/// | 112 to 127 | debug registers |
///
/// Bound registers have no bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RegSet(u128);

impl RegSet {
    /// The empty set.
    pub const EMPTY: Self = Self(0);
    /// The 16 general-purpose registers `rax` to `r15`.
    pub const GPR16: Self = Self(0xffff);
    /// The 32 general-purpose registers `rax` to `r31`.
    pub const GPR32: Self = Self(0xffff_ffff);
    /// The 32 vector registers.
    pub const VEC32: Self = Self(0xffff_ffff << 32);

    fn bit(reg: Reg) -> Option<u32> {
        let n = u32::from(reg.number());
        let base = match reg.class() {
            RegClass::Gpr => 0,
            RegClass::Xmm | RegClass::Ymm | RegClass::Zmm => 32,
            RegClass::Seg => 64,
            RegClass::Ip => return Some(70),
            RegClass::Mmx => 72,
            RegClass::X87 => 80,
            RegClass::Mask => 88,
            RegClass::Ctrl => 96,
            RegClass::Debug => 112,
            RegClass::Bnd => return None,
        };
        Some(base + n)
    }

    fn reg_of(bit: u32) -> Option<Reg> {
        let n = u8::try_from(bit & 31).ok()?;
        Some(match bit {
            0..=31 => Reg::gpr(n, 64),
            32..=63 => Reg::xmm(n),
            64..=69 => Seg::from_number(n)?.reg(),
            70 => Reg::RIP,
            72..=79 => Reg::mmx(n),
            80..=87 => Reg::st(n),
            88..=95 => Reg::pack(RegClass::Mask, n & 7, 3, false),
            96..=111 => Reg::cr(n),
            112..=127 => Reg::dr(n),
            _ => return None,
        })
    }

    /// Gives the raw bits.
    #[must_use]
    pub const fn bits(self) -> u128 {
        self.0
    }

    /// Adds the full register of `reg`.
    pub fn insert(&mut self, reg: Reg) {
        if let Some(b) = Self::bit(reg) {
            self.0 |= 1 << b;
        }
    }

    /// Gives the set with the full register of `reg` added.
    #[must_use]
    pub fn with(mut self, reg: Reg) -> Self {
        self.insert(reg);
        self
    }

    /// Tells if the set holds the full register of `reg`.
    #[must_use]
    pub fn contains(self, reg: Reg) -> bool {
        Self::bit(reg).is_some_and(|b| self.0 & (1 << b) != 0)
    }

    /// Gives the union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Tells if the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Gives the number of registers in the set.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// Gives the registers of the set in bit order.
    pub fn iter(self) -> impl Iterator<Item = Reg> {
        (0..128u32)
            .filter(move |b| self.0 & (1 << b) != 0)
            .filter_map(Self::reg_of)
    }
}

impl FromIterator<Reg> for RegSet {
    fn from_iter<T: IntoIterator<Item = Reg>>(iter: T) -> Self {
        let mut set = Self::EMPTY;
        for reg in iter {
            set.insert(reg);
        }
        set
    }
}
