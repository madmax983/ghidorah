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
use std::collections::BTreeSet;
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
        // `PF_X`, `PF_W` and `PF_R` have the values of the Ghidra bits.
        let mut bits = 0;
        if p_flags & 0x1 != 0 {
            bits |= Self::EXECUTE.0;
        }
        if p_flags & 0x2 != 0 {
            bits |= Self::WRITE.0;
        }
        if p_flags & 0x4 != 0 {
            bits |= Self::READ.0;
        }
        Self(bits)
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
        self.regions.get(va)
    }

    /// Gives the mapped address nearest to `va`. A mapped `va` gives itself.
    #[must_use]
    pub fn nearest(&self, va: u64) -> Option<u64> {
        self.regions.nearest(va)
    }

    /// Gives `region` with its file part cut to the region size and to the file bytes.
    fn normalize(&self, mut region: Region) -> Region {
        let file_len = u64::try_from(self.file.len()).unwrap_or(u64::MAX);
        if region.file_off > file_len {
            region.file_off = file_len;
        }
        let in_file = file_len.saturating_sub(region.file_off);
        let vsize = u64::try_from(region.va.len()).unwrap_or(u64::MAX);
        region.file_size = region.file_size.min(in_file).min(vsize);
        region
    }

    /// Adds a region. A part of an old region under the new region goes away.
    ///
    /// The map cuts `file_size` to the region size and to the file bytes after `file_off`.
    /// The result lists the old ranges that the new region replaced, in address order.
    pub fn map(&mut self, region: Region) -> Vec<Range> {
        let region = self.normalize(region);
        let new = region.va;
        let old: Vec<(Range, Region)> = self.regions.overlapping(new).to_vec();
        let mut replaced = Vec::with_capacity(old.len());
        for (range, value) in old {
            self.regions.remove_at(range.first);
            replaced.push(Range {
                first: range.first.max(new.first),
                last: range.last.min(new.last),
            });
            for keep in outside(range, new) {
                // The part is outside `new` and outside the other old ranges.
                let _ = self.regions.insert(keep, piece(&value, keep));
            }
        }
        // No old range overlaps `new` now.
        let _ = self.regions.insert(new, region);
        replaced
    }

    /// Adds many regions in one sweep. A later region wins where two regions overlap.
    ///
    /// The old regions of the map come before the new ones. The work is `O(n log n)`.
    /// The result gives the list index of each new region that covers a part of an
    /// earlier region, in index order.
    pub fn map_all(&mut self, regions: Vec<Region>) -> Vec<usize> {
        let old_count = self.regions.len();
        let mut all: Vec<Region> = std::mem::take(&mut self.regions)
            .iter()
            .map(|(_, r)| r.clone())
            .collect();
        all.extend(regions.into_iter().map(|r| self.normalize(r)));
        let (parts, covering) = sweep(&all);
        let entries: Vec<(Range, Region)> = parts
            .into_iter()
            .filter_map(|(part, owner)| all.get(owner).map(|r| (part, piece(r, part))))
            .collect();
        // The sweep gives disjoint parts, so the bulk insert cannot fail.
        let _ = self.regions.extend_sorted(entries);
        covering
            .into_iter()
            .filter_map(|i| i.checked_sub(old_count))
            .collect()
    }

    /// Reads `len` bytes at `va`. Bytes in a zero tail read as zero.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Unmapped`] when an address of the read is in no region.
    /// Returns [`MemError::Overflow`] when the read goes past `u64::MAX`.
    /// Returns [`MemError::TooLong`] when `len` is above `limits.file_size`.
    pub fn read(&self, va: u64, len: u64, limits: &Limits) -> Result<Bytes<'_>, MemError> {
        if len == 0 {
            return Ok(Cow::Borrowed(&[]));
        }
        if len > limits.file_size {
            return Err(MemError::TooLong {
                len,
                max: limits.file_size,
            });
        }
        let last = ghidorah_kernel::range_last(va, len).ok_or(MemError::Overflow { va, len })?;
        let mut out: Option<Vec<u8>> = None;
        let mut cur = va;
        loop {
            let Some((range, region)) = self.regions.find(cur) else {
                return Err(MemError::Unmapped {
                    va: cur,
                    nearest: self.regions.nearest(cur),
                });
            };
            let end = range.last.min(last);
            let part = self.part(region, cur, end);
            if out.is_none()
                && end == last
                && let Some(bytes) = part.as_borrowed()
            {
                return Ok(Cow::Borrowed(bytes));
            }
            let buf = out.get_or_insert_with(|| {
                Vec::with_capacity(usize::try_from(len).unwrap_or_default())
            });
            part.append_to(buf);
            if end == last {
                return Ok(Cow::Owned(out.unwrap_or_default()));
            }
            // Here `end < last`, so the next address exists.
            cur = end.saturating_add(1);
        }
    }

    /// Gives the bytes of `region` from `first` to `last`. Both are in the region.
    fn part<'a>(&'a self, region: &Region, first: u64, last: u64) -> Part<'a> {
        let delta = first.saturating_sub(region.va.first);
        let count = last.saturating_sub(first).saturating_add(1);
        let from_file = region.file_size.saturating_sub(delta).min(count);
        let start = usize::try_from(region.file_off.saturating_add(delta)).unwrap_or(usize::MAX);
        let take = usize::try_from(from_file).unwrap_or_default();
        let bytes = start
            .checked_add(take)
            .and_then(|end| self.file.get(start..end))
            .unwrap_or_default();
        Part {
            bytes,
            zeros: count.saturating_sub(from_file),
        }
    }

    /// Gives the file offset of the byte at `va`.
    ///
    /// The result is `None` for a byte in a zero tail or outside every region.
    #[must_use]
    pub fn va_to_file(&self, va: u64) -> Option<u64> {
        let region = self.regions.get(va)?;
        ghidorah_kernel::va_to_file(&region.mapping(), va)
    }
}

/// The bytes of one region part: file bytes, then a run of zeros.
struct Part<'a> {
    bytes: &'a [u8],
    zeros: u64,
}

impl<'a> Part<'a> {
    /// Gives the file bytes when the part has no zeros.
    const fn as_borrowed(&self) -> Option<&'a [u8]> {
        if self.zeros == 0 {
            Some(self.bytes)
        } else {
            None
        }
    }

    /// Adds the bytes of the part to `out`.
    fn append_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.bytes);
        let zeros = usize::try_from(self.zeros).unwrap_or_default();
        out.resize(out.len().saturating_add(zeros), 0);
    }
}

/// Gives the parts of `range` outside `cut`: at most one on each side.
fn outside(range: Range, cut: Range) -> Vec<Range> {
    let mut out = Vec::with_capacity(2);
    if range.first < cut.first
        && let Some(last) = cut.first.checked_sub(1)
    {
        out.push(Range {
            first: range.first,
            last: last.min(range.last),
        });
    }
    if range.last > cut.last
        && let Some(first) = cut.last.checked_add(1)
    {
        out.push(Range {
            first: first.max(range.first),
            last: range.last,
        });
    }
    out
}

/// Gives the part `va` of `region` with the matching file part. `va` is in `region.va`.
fn piece(region: &Region, va: Range) -> Region {
    let delta = va.first.saturating_sub(region.va.first);
    let skip = delta.min(region.file_size);
    let len = u64::try_from(va.len()).unwrap_or(u64::MAX);
    Region {
        name: region.name.clone(),
        va,
        file_off: region.file_off.saturating_add(skip),
        file_size: region.file_size.saturating_sub(skip).min(len),
        perms: region.perms,
        source: region.source,
    }
}

/// Splits the addresses under `regions` into parts with one owner each.
///
/// The owner of a part is the last region of the list that holds it. Adjacent parts with
/// the same owner join. The second result lists each region that covers a part of an
/// earlier region, in index order.
fn sweep(regions: &[Region]) -> (Vec<(Range, usize)>, Vec<usize>) {
    // The events use `u128` points, so the end after `u64::MAX` has a value.
    // At one point, the ends (`false`) come before the starts (`true`).
    let mut events: Vec<(u128, bool, usize)> = Vec::with_capacity(regions.len().saturating_mul(2));
    for (i, r) in regions.iter().enumerate() {
        events.push((u128::from(r.va.first), true, i));
        events.push((u128::from(r.va.last).saturating_add(1), false, i));
    }
    events.sort_unstable();
    let mut live: BTreeSet<usize> = BTreeSet::new();
    // The live regions that overlap no earlier region so far.
    let mut unmarked: BTreeSet<usize> = BTreeSet::new();
    let mut covering = BTreeSet::new();
    let mut parts: Vec<(Range, usize)> = Vec::new();
    let mut at = 0;
    while let Some(&(point, _, _)) = events.get(at) {
        while let Some(&(p, start, i)) = events.get(at)
            && p == point
        {
            if start {
                if live.first().is_some_and(|low| *low < i) {
                    covering.insert(i);
                } else {
                    unmarked.insert(i);
                }
                // Each live region with a higher index now overlaps region `i`.
                let higher: Vec<usize> = unmarked.range(i.saturating_add(1)..).copied().collect();
                for h in higher {
                    unmarked.remove(&h);
                    covering.insert(h);
                }
                live.insert(i);
            } else {
                live.remove(&i);
                unmarked.remove(&i);
            }
            at = at.saturating_add(1);
        }
        let (Some(&owner), Some(&(next, _, _))) = (live.last(), events.get(at)) else {
            continue;
        };
        let (Ok(first), Ok(last)) = (u64::try_from(point), u64::try_from(next.saturating_sub(1)))
        else {
            continue;
        };
        match parts.last_mut() {
            Some((prev, o)) if *o == owner && prev.last.checked_add(1) == Some(first) => {
                prev.last = last;
            }
            _ => parts.push((Range { first, last }, owner)),
        }
    }
    (parts, covering.into_iter().collect())
}
