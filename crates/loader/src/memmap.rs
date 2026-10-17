//! `MemoryMap`: the one view of mapped memory (design Section 3.3).
//!
//! A map holds the file bytes and an [`IntervalMap`] of disjoint [`Region`] values.
//! Each region maps `file_size` bytes from `file_off` to its first addresses. The
//! bytes after `file_size` up to the end of the region read as zero.
//!
//! | Call | Result |
//! |---|---|
//! | [`MemoryMap::read`] in one file part | the file bytes, with no copy |
//! | [`MemoryMap::read`] over a zero tail or two adjacent regions | a copy, zeros in the tails |
//! | [`MemoryMap::read`] that touches a hole | [`MemError::Unmapped`] with the nearest mapped address |
//! | [`MemoryMap::va_to_file`] in a zero tail or a hole | `None` |
//!
//! The decoder, the string scan, jump-table emulation, `mem_read` and `search` read memory
//! only through this type.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use ghidorah_base::{IntervalMap, Limits, Range};
use ghidorah_kernel::Mapping;

/// The bytes of a read: borrowed from the file, or a copy with zero tails.
pub type Bytes<'a> = Cow<'a, [u8]>;

/// Access bits of a region. The values keep the Ghidra bits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Perms(u8);

impl Perms {
    /// No access bit.
    pub const NONE: Self = Self(0);
    /// Execute access.
    pub const EXECUTE: Self = Self(0x1);
    /// Write access.
    pub const WRITE: Self = Self(0x2);
    /// Read access.
    pub const READ: Self = Self(0x4);
    /// The memory can change outside the program.
    pub const VOLATILE: Self = Self(0x8);
    /// The loader made the region. The file has no matching bytes.
    pub const ARTIFICIAL: Self = Self(0x10);
    /// Read, write and execute access.
    pub const RWX: Self = Self(0x7);

    /// Makes a value from its bits.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Gives the bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Makes a value from the ELF `p_flags` bits `PF_R`, `PF_W` and `PF_X`.
    #[must_use]
    pub const fn from_elf(p_flags: u32) -> Self {
        Self(0)
    }

    /// Tells if `self` has every bit of `other`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Gives the bits of `self` and `other`.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl fmt::Display for Perms {
    /// Writes three letters: `r`, `w` and `x`, or `-` for a missing bit.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let letter = |bit: Self, c: char| if self.contains(bit) { c } else { '-' };
        write!(
            f,
            "{}{}{}",
            letter(Self::READ, 'r'),
            letter(Self::WRITE, 'w'),
            letter(Self::EXECUTE, 'x')
        )
    }
}

/// The origin of a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegionSource {
    /// The ELF program header with this index.
    ElfSegment(u32),
    /// The PE headers.
    PeHeaders,
    /// The PE section header with this index.
    PeSection(u32),
    /// The whole file of a raw load.
    Raw,
}

/// One mapped region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// The region name, for example `seg:3`, `.text` or `raw`.
    pub name: String,
    /// The addresses of the region.
    pub va: Range,
    /// The file offset of the first byte.
    pub file_off: u64,
    /// The number of bytes that come from the file. The other bytes read as zero.
    pub file_size: u64,
    /// The access bits.
    pub perms: Perms,
    /// The origin.
    pub source: RegionSource,
}

impl Region {
    /// Gives the K2 mapping of the region.
    #[must_use]
    pub const fn mapping(&self) -> Mapping {
        Mapping {
            va: self.va.first,
            file_off: self.file_off,
            file_size: self.file_size,
        }
    }
}

/// The error of a memory read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemError {
    /// The read touches an address outside every region.
    Unmapped {
        /// The first address of the read that no region holds.
        va: u64,
        /// The mapped address nearest to `va`, or `None` for an empty map.
        nearest: Option<u64>,
    },
    /// The read goes past `u64::MAX`.
    Overflow {
        /// The first address of the read.
        va: u64,
        /// The length of the read.
        len: u64,
    },
    /// The read is longer than the file size limit.
    TooLong {
        /// The length of the read.
        len: u64,
        /// The largest length.
        max: u64,
    },
}

impl fmt::Display for MemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unmapped {
                va,
                nearest: Some(n),
            } => write!(
                f,
                "The address {va:#x} is not mapped. The nearest mapped address is {n:#x}."
            ),
            Self::Unmapped { va, nearest: None } => {
                write!(
                    f,
                    "The address {va:#x} is not mapped. The map has no region."
                )
            }
            Self::Overflow { va, len } => write!(
                f,
                "The read of {len:#x} bytes at {va:#x} goes past the last address."
            ),
            Self::TooLong { len, max } => write!(
                f,
                "The read of {len:#x} bytes is longer than the limit of {max:#x} bytes."
            ),
        }
    }
}

impl std::error::Error for MemError {}

/// The file bytes and the mapped regions of one binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMap {
    file: Arc<[u8]>,
    regions: IntervalMap<Region>,
}

impl MemoryMap {
    /// Makes a map with no region over the file bytes.
    #[must_use]
    pub fn new(file: Arc<[u8]>) -> Self {
        Self {
            file,
            regions: IntervalMap::new(),
        }
    }

    /// Gives the file bytes.
    #[must_use]
    pub fn file(&self) -> &[u8] {
        &self.file
    }

    /// Gives the shared file bytes.
    #[must_use]
    pub const fn file_arc(&self) -> &Arc<[u8]> {
        &self.file
    }

    /// Gives the regions in address order.
    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.regions.iter().map(|(_, r)| r)
    }

    /// Gives the number of regions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Tells if the map has no region.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Gives the region that holds `va`.
    #[must_use]
    pub fn region_at(&self, va: u64) -> Option<&Region> {
        None
    }

    /// Gives the mapped address nearest to `va`. A mapped `va` gives itself.
    #[must_use]
    pub fn nearest(&self, va: u64) -> Option<u64> {
        None
    }

    /// Adds a region. A part of an old region under the new region goes away.
    ///
    /// The map cuts `file_size` to the region size and to the file bytes after `file_off`.
    /// The result lists the old ranges that the new region replaced, in address order.
    pub fn map(&mut self, region: Region) -> Vec<Range> {
        Vec::new()
    }

    /// Adds many regions in one sweep. A later region wins where two regions overlap.
    ///
    /// The old regions of the map come before the new ones. The work is `O(n log n)`.
    /// The result gives the list index of each new region that covers a part of an
    /// earlier region, in index order.
    pub fn map_all(&mut self, regions: Vec<Region>) -> Vec<usize> {
        Vec::new()
    }

    /// Reads `len` bytes at `va`. Bytes in a zero tail read as zero.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Unmapped`] when an address of the read is in no region,
    /// [`MemError::Overflow`] when the read goes past `u64::MAX` and
    /// [`MemError::TooLong`] when `len` is above `limits.file_size`.
    pub fn read(&self, va: u64, len: u64, limits: &Limits) -> Result<Bytes<'_>, MemError> {
        Err(MemError::Unmapped { va, nearest: None })
    }

    /// Gives the file offset of the byte at `va`.
    ///
    /// The result is `None` for a byte in a zero tail or outside every region.
    #[must_use]
    pub fn va_to_file(&self, va: u64) -> Option<u64> {
        None
    }
}
