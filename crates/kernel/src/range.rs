//! K2: checked range math over `u64` addresses and offsets.
//!
//! Ranges are inclusive: `Range { first, last }` with `first <= last`.
//! So a range can end at `u64::MAX`. No code computes `start + len` without [`range_last`].
//!
//! Verus proves that no function overflows. It also proves the exact result of each function.

#[cfg(not(verus_only))]
use ghidorah_spec::{proof, verus_spec, verus_verify};
#[cfg(verus_only)]
use vstd::prelude::*;

/// An inclusive range of `u64` values.
///
/// A valid range has `first <= last`. The constructors give only valid ranges.
/// The methods treat a range with `first > last` as empty.
#[verus_verify]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Range {
    /// The first value of the range.
    pub first: u64,
    /// The last value of the range.
    pub last: u64,
}

/// The file view of one mapped region: `file_size` bytes at `va` come from `file_off`.
///
/// The bytes after `file_size` up to the memory size are the zero-fill tail. They have no file offset.
#[verus_verify]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mapping {
    /// The virtual address of the first byte.
    pub va: u64,
    /// The file offset of the first byte.
    pub file_off: u64,
    /// The count of bytes that come from the file.
    pub file_size: u64,
}

#[cfg(verus_only)]
verus! {

impl Range {
    /// The range has `first <= last`.
    pub open spec fn wf(self) -> bool {
        self.first <= self.last
    }

    /// The range holds `x`.
    pub open spec fn has(self, x: int) -> bool {
        self.first <= x && x <= self.last
    }
}

} // verus!

/// Gives the last value of the range of `len` values from `start`.
///
/// Gives `None` when `len` is 0 or when the range goes past `u64::MAX`.
#[must_use]
#[verus_spec(r =>
    ensures
        match r {
            Some(last) => len > 0 && start + len - 1 <= u64::MAX && last == start + len - 1,
            None => len == 0 || start + len - 1 > u64::MAX,
        },
)]
#[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
pub fn range_last(start: u64, len: u64) -> Option<u64> {
    if len == 0 || len - 1 > u64::MAX - start {
        None
    } else {
        Some(start + (len - 1))
    }
}

#[verus_verify]
impl Range {
    /// Makes the range `[first, last]`.
    ///
    /// Gives `None` when `first > last`.
    #[must_use]
    #[verus_spec(r =>
        ensures
            match r {
                Some(v) => first <= last && v.first == first && v.last == last,
                None => first > last,
            },
    )]
    pub fn new(first: u64, last: u64) -> Option<Self> {
        if first <= last {
            Some(Self { first, last })
        } else {
            None
        }
    }

    /// Makes the range of `len` values from `start`.
    ///
    /// Gives `None` when `len` is 0 or when the range goes past `u64::MAX`.
    #[must_use]
    #[verus_spec(r =>
        ensures
            match r {
                Some(v) => v.wf() && v.first == start && v.last == start + len - 1 && len > 0,
                None => len == 0 || start + len - 1 > u64::MAX,
            },
    )]
    pub fn with_len(start: u64, len: u64) -> Option<Self> {
        let last = range_last(start, len)?;
        Some(Self { first: start, last })
    }

    /// Makes the range that holds only `x`.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r.first == x && r.last == x,
    )]
    pub fn single(x: u64) -> Self {
        Self { first: x, last: x }
    }

    /// Gives the count of values in the range. An empty range gives 0.
    #[must_use]
    #[verus_spec(r =>
        ensures
            self.wf() ==> r == self.last - self.first + 1,
            !self.wf() ==> r == 0,
    )]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn len(&self) -> u128 {
        if self.first <= self.last {
            u128::from(self.last) - u128::from(self.first) + 1
        } else {
            0
        }
    }

    /// Tells if the range holds no value, so `first > last`.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r == !self.wf(),
    )]
    pub fn is_empty(&self) -> bool {
        self.first > self.last
    }

    /// Tells if the range holds `x`.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r == self.has(x as int),
    )]
    pub fn contains(&self, x: u64) -> bool {
        self.first <= x && x <= self.last
    }

    /// Tells if the two ranges hold a common value.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r == (exists|x: int| self.has(x) && other.has(x)),
    )]
    pub fn overlaps(&self, other: &Self) -> bool {
        let lo = if self.first >= other.first {
            self.first
        } else {
            other.first
        };
        let hi = if self.last <= other.last {
            self.last
        } else {
            other.last
        };
        proof! {
            if lo <= hi {
                assert(self.has(lo as int) && other.has(lo as int));
            }
        }
        lo <= hi
    }

    /// Gives the offset of `x` from `first`, or `None` when the range does not hold `x`.
    #[must_use]
    #[verus_spec(r =>
        ensures
            match r {
                Some(o) => self.has(x as int) && o == x - self.first,
                None => !self.has(x as int),
            },
    )]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn offset_in(&self, x: u64) -> Option<u64> {
        if self.contains(x) {
            Some(x - self.first)
        } else {
            None
        }
    }
}

/// Gives the file offset of the address `va` in the mapping `map`.
///
/// Gives `None` when `va` is outside `[map.va, map.va + map.file_size)`.
/// So the zero-fill tail gives `None`. An offset past `u64::MAX` also gives `None`.
#[must_use]
#[verus_spec(r =>
    ensures
        match r {
            Some(o) => map.va <= va && va < map.va + map.file_size
                && o == map.file_off + (va - map.va),
            None => !(map.va <= va && va < map.va + map.file_size)
                || map.file_off + (va - map.va) > u64::MAX,
        },
)]
#[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
pub fn va_to_file(map: &Mapping, va: u64) -> Option<u64> {
    if va < map.va {
        return None;
    }
    let delta = va - map.va;
    if delta >= map.file_size {
        return None;
    }
    map.file_off.checked_add(delta)
}
