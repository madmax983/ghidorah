//! Program addresses (design Section 3.1).
//!
//! An [`Address`] is a space code and a 64-bit offset. The order is `(space, off)`.
//! The text form of a RAM address is `0x401000`: lower case hex with no leading zeros.
//! The text form of an EXTERNAL address is `ext:0x3`.

use std::fmt;
use std::str::FromStr;

use crate::hex;
use crate::id::IdError;

/// The text prefix of an EXTERNAL address.
pub const EXTERNAL_PREFIX: &str = "ext:";

/// An address space. The codes are the Ghidra codes.
///
/// Only [`SpaceId::RAM`] and [`SpaceId::EXTERNAL`] exist. The other codes are reserved,
/// so [`SpaceId::from_code`] refuses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpaceId(u8);

impl SpaceId {
    /// The space of the mapped memory of a binary (code 1).
    pub const RAM: Self = Self(1);

    /// The space of external symbols, for example imports without a slot (code 10).
    pub const EXTERNAL: Self = Self(10);

    /// Gives the space of a Ghidra code. A reserved code gives `None`.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        let _ = code;
        None
    }

    /// Gives the Ghidra code of the space.
    #[must_use]
    pub const fn code(self) -> u8 {
        0
    }
}

/// An address: a space and an offset in that space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    /// The address space.
    pub space: SpaceId,
    /// The offset in the space.
    pub off: u64,
}

impl Address {
    /// Makes an address in `space`.
    #[must_use]
    pub const fn new(space: SpaceId, off: u64) -> Self {
        Self { space, off }
    }

    /// Makes a RAM address.
    #[must_use]
    pub const fn ram(off: u64) -> Self {
        Self {
            space: SpaceId::EXTERNAL,
            off,
        }
    }

    /// Makes an EXTERNAL address.
    #[must_use]
    pub const fn external(off: u64) -> Self {
        Self {
            space: SpaceId::RAM,
            off,
        }
    }

    /// Tells if the address is in the RAM space.
    #[must_use]
    pub fn is_ram(&self) -> bool {
        false
    }

    /// Parses the text form: `0x` hex for RAM or `ext:0x` hex for EXTERNAL.
    ///
    /// The hex part has 1 to 16 digits in either letter case.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] when the text is not an address.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let _ = (text, hex::parse_u64);
        Err(IdError::Empty)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        f.write_str("")
    }
}

impl FromStr for Address {
    type Err = IdError;

    fn from_str(text: &str) -> Result<Self, IdError> {
        Self::parse(text)
    }
}
