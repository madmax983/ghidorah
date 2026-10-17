//! The string manager (design Sections 3.4 and 7.6).
//!
//! The key is the RAM offset of the first byte. Only the string analyzer writes this table,
//! so a record carries no provenance.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::Range;

use crate::listing::starts_in;

/// The encoding of a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    /// ASCII.
    Ascii,
    /// UTF-8 with at least one byte above 0x7f.
    Utf8,
    /// UTF-16 little-endian.
    Utf16Le,
}

impl Encoding {
    /// Gives the output name, for example `utf16le`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf8 => "utf8",
            Self::Utf16Le => "utf16le",
        }
    }
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StrInfo {
    /// The encoding.
    pub encoding: Encoding,
    /// The length in bytes, without the terminator.
    pub len: u32,
    /// A reference points to the string.
    pub referenced: bool,
}

/// The strings of one layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Strings {
    map: BTreeMap<u64, StrInfo>,
}

impl Strings {
    /// Gives the number of strings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Tells if the layer has no string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Gives the string at `off`.
    #[must_use]
    pub fn get(&self, off: u64) -> Option<&StrInfo> {
        self.map.get(&off)
    }

    /// Gives the strings that start in `range`, in address order.
    pub fn in_range(&self, range: Range) -> impl Iterator<Item = (u64, &StrInfo)> {
        starts_in(&self.map, range)
    }

    /// Gives all strings in address order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &StrInfo)> {
        self.map.iter().map(|(k, v)| (*k, v))
    }

    /// Sets the string at `off`. Gives the old record.
    pub(crate) fn insert(&mut self, off: u64, info: StrInfo) -> Option<StrInfo> {
        self.map.insert(off, info)
    }

    /// Removes the string at `off` and gives it.
    pub(crate) fn remove(&mut self, off: u64) -> Option<StrInfo> {
        self.map.remove(&off)
    }
}
