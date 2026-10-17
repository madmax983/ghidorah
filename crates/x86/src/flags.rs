//! Sets of status flags.

use std::fmt;

/// A set of x86 status flags.
///
/// | Bit | Flag |
/// |---|---|
/// | 0 | CF |
/// | 1 | PF |
/// | 2 | AF |
/// | 3 | ZF |
/// | 4 | SF |
/// | 5 | OF |
/// | 6 | DF |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FlagSet(u8);

impl FlagSet {
    /// No flag.
    pub const NONE: Self = Self(0);
    /// The carry flag.
    pub const CF: Self = Self(1);
    /// The parity flag.
    pub const PF: Self = Self(1 << 1);
    /// The auxiliary carry flag.
    pub const AF: Self = Self(1 << 2);
    /// The zero flag.
    pub const ZF: Self = Self(1 << 3);
    /// The sign flag.
    pub const SF: Self = Self(1 << 4);
    /// The overflow flag.
    pub const OF: Self = Self(1 << 5);
    /// The direction flag.
    pub const DF: Self = Self(1 << 6);
    /// The six arithmetic flags CF, PF, AF, ZF, SF and OF.
    pub const ARITH: Self = Self(0x3f);

    const NAMES: [&str; 7] = ["cf", "pf", "af", "zf", "sf", "of", "df"];
    /// The bit of each flag in the EFLAGS register.
    const EFLAGS_BITS: [u16; 7] = [0, 2, 4, 6, 7, 11, 10];

    /// Makes a set from its bits. The function ignores bit 7.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & 0x7f)
    }

    /// Gives the bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Gives the union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Gives the flags of `self` that are not in `other`.
    #[must_use]
    pub const fn minus(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Tells if every flag of `other` is in the set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Tells if the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Gives the set as a mask in the EFLAGS layout (design Section 6.2).
    /// CF is bit 0, PF bit 2, AF bit 4, ZF bit 6, SF bit 7, DF bit 10 and OF bit 11.
    #[must_use]
    pub fn to_eflags(self) -> u16 {
        Self::EFLAGS_BITS
            .iter()
            .enumerate()
            .filter(|(i, _)| self.0 & (1 << i) != 0)
            .fold(0, |acc, (_, b)| acc | (1 << b))
    }
}

impl fmt::Display for FlagSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (i, name) in Self::NAMES.iter().enumerate() {
            if self.0 & (1 << i) != 0 {
                if !first {
                    f.write_str(",")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}
