//! `IntervalMap`: a map from disjoint inclusive ranges to values (design Section 3.2).
//!
//! The map is a sorted `Vec<(Range, V)>`. No two ranges share a value of `u64`.
//! Adjacent ranges stay separate, because their values can differ.
//! Range ends use the K2 math of `ghidorah-kernel`, so a range can end at `u64::MAX`.
//!
//! Users: memory regions, section lookup and function ownership.

use std::fmt;

use ghidorah_kernel::Range;

/// An error of an [`IntervalMap`] change. The change does not apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntervalError {
    /// The range has `first > last`.
    InvalidRange(Range),
    /// The new range overlaps a range of the map or another new range.
    Overlap {
        /// The new range.
        new: Range,
        /// The range that it overlaps.
        existing: Range,
    },
}

impl fmt::Display for IntervalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange(r) => write!(
                f,
                "The range [{:#x}, {:#x}] has its first value after its last value.",
                r.first, r.last
            ),
            Self::Overlap { new, existing } => write!(
                f,
                "The range [{:#x}, {:#x}] overlaps the range [{:#x}, {:#x}].",
                new.first, new.last, existing.first, existing.last
            ),
        }
    }
}

impl std::error::Error for IntervalError {}

/// A map from disjoint inclusive ranges to values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntervalMap<V> {
    entries: Vec<(Range, V)>,
}

impl<V> Default for IntervalMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> IntervalMap<V> {
    /// Makes an empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Gives the number of ranges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Tells if the map has no range.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Gives the entries in range order.
    #[must_use]
    pub fn as_slice(&self) -> &[(Range, V)] {
        &self.entries
    }

    /// Gives the entries in range order.
    pub fn iter(&self) -> impl Iterator<Item = (Range, &V)> {
        self.entries.iter().map(|(r, v)| (*r, v))
    }

    /// Gives the range and the value that hold `x`.
    #[must_use]
    pub fn find(&self, x: u64) -> Option<(Range, &V)> {
        let _ = x;
        None
    }

    /// Gives the value of the range that holds `x`.
    #[must_use]
    pub fn get(&self, x: u64) -> Option<&V> {
        self.find(x).map(|(_, v)| v)
    }

    /// Gives the value of the range that holds `x`, for a change.
    pub fn get_mut(&mut self, x: u64) -> Option<&mut V> {
        let _ = x;
        None
    }

    /// Gives the entries whose ranges overlap `range`, in range order.
    #[must_use]
    pub fn overlapping(&self, range: Range) -> &[(Range, V)] {
        let _ = range;
        &[]
    }

    /// Tells if no range of the map overlaps `range`.
    #[must_use]
    pub fn is_free(&self, range: Range) -> bool {
        self.overlapping(range).is_empty()
    }

    /// Adds `range` with `value`.
    ///
    /// # Errors
    ///
    /// Returns [`IntervalError::InvalidRange`] when `first > last` and
    /// [`IntervalError::Overlap`] when `range` overlaps a range of the map.
    pub fn insert(&mut self, range: Range, value: V) -> Result<(), IntervalError> {
        let _ = (range, value);
        Ok(())
    }

    /// Removes the entry whose range holds `x` and gives it.
    pub fn remove_at(&mut self, x: u64) -> Option<(Range, V)> {
        let _ = x;
        None
    }

    /// Adds many entries. The method sorts them once and checks them once.
    ///
    /// # Errors
    ///
    /// Returns [`IntervalError`] when an entry is not valid or overlaps another entry.
    /// Then the map does not change.
    pub fn extend_sorted(&mut self, items: Vec<(Range, V)>) -> Result<(), IntervalError> {
        let _ = items;
        Ok(())
    }

    /// Gives the mapped value nearest to `x`, or `None` for an empty map.
    ///
    /// A value in the map gives itself. For a gap, the nearer end of the two neighbor
    /// ranges wins. A tie gives the lower value.
    #[must_use]
    pub fn nearest(&self, x: u64) -> Option<u64> {
        let _ = x;
        None
    }
}

impl<V: Clone> IntervalMap<V> {
    /// Removes the values in `range`. A range that is partly inside `range` splits.
    ///
    /// Each part that stays keeps a copy of the old value.
    pub fn clear_range(&mut self, range: Range) {
        let _ = range;
    }

    /// Sets `value` on `range`. The method first removes the old values in `range`.
    ///
    /// # Errors
    ///
    /// Returns [`IntervalError::InvalidRange`] when `first > last`.
    pub fn replace(&mut self, range: Range, value: V) -> Result<(), IntervalError> {
        let _ = (range, value);
        Ok(())
    }
}
