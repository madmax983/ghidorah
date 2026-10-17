//! Computed default names (design Section 3.4).
//!
//! The program database computes these names on read and never stores them.
//! The text is a prefix, `_` and the offset in lower case hex with at least 8 digits:
//! `FUN_00401130`. Input accepts 1 to 16 digits in either letter case.

use std::fmt;

use crate::address::{Address, SpaceId};
use crate::hex;

/// The kind of a default name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DefaultKind {
    /// `FUN_`: a function.
    Fun,
    /// `LAB_`: a code label.
    Lab,
    /// `DAT_`: a data item.
    Dat,
    /// `EXT_`: an EXTERNAL address.
    Ext,
}

impl DefaultKind {
    /// All kinds.
    pub const ALL: [Self; 4] = [Self::Fun, Self::Lab, Self::Dat, Self::Ext];

    /// Gives the prefix of the kind, for example `FUN_`.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Fun => "FUN_",
            Self::Lab => "LAB_",
            Self::Dat => "DAT_",
            Self::Ext => "EXT_",
        }
    }

    /// Gives the address space of the kind.
    #[must_use]
    pub const fn space(self) -> SpaceId {
        match self {
            Self::Ext => SpaceId::EXTERNAL,
            Self::Fun | Self::Lab | Self::Dat => SpaceId::RAM,
        }
    }
}

/// A default name: a kind and an address.
///
/// `FUN_`, `LAB_` and `DAT_` name RAM addresses. `EXT_` names EXTERNAL addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefaultName {
    /// The kind of the name.
    pub kind: DefaultKind,
    /// The address that the name stands for.
    pub addr: Address,
}

impl DefaultName {
    /// Makes the default name of `kind` at `off`, in the space of the kind.
    #[must_use]
    pub const fn new(kind: DefaultKind, off: u64) -> Self {
        Self {
            kind,
            addr: Address::new(kind.space(), off),
        }
    }

    /// Parses a default name such as `FUN_00401000`.
    ///
    /// Gives `None` when the text is not a prefix and 1 to 16 hex digits.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        DefaultKind::ALL.into_iter().find_map(|kind| {
            let digits = text.strip_prefix(kind.prefix())?;
            hex::parse_digits(digits).map(|off| Self::new(kind, off))
        })
    }
}

impl fmt::Display for DefaultName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:08x}", self.kind.prefix(), self.addr.off)
    }
}
