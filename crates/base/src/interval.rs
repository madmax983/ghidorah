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

    /// Gives the index of the entry that holds `x`.
    fn index_of(&self, x: u64) -> Option<usize> {
        let after = self.entries.partition_point(|(r, _)| r.first <= x);
        let i = after.checked_sub(1)?;
        let (r, _) = self.entries.get(i)?;
        (r.last >= x).then_some(i)
    }

    /// Gives the index range of the entries that overlap `range`.
    fn overlap_span(&self, range: Range) -> std::ops::Range<usize> {
        if range.first > range.last {
            return 0..0;
        }
        let start = self.entries.partition_point(|(r, _)| r.last < range.first);
        let end = self.entries.partition_point(|(r, _)| r.first <= range.last);
        start..end.max(start)
    }

    /// Gives the range and the value that hold `x`.
    #[must_use]
    pub fn find(&self, x: u64) -> Option<(Range, &V)> {
        let (r, v) = self.entries.get(self.index_of(x)?)?;
        Some((*r, v))
    }

    /// Gives the value of the range that holds `x`.
    #[must_use]
    pub fn get(&self, x: u64) -> Option<&V> {
        self.find(x).map(|(_, v)| v)
    }

    /// Gives the value of the range that holds `x`, for a change.
    pub fn get_mut(&mut self, x: u64) -> Option<&mut V> {
        let i = self.index_of(x)?;
        self.entries.get_mut(i).map(|(_, v)| v)
    }

    /// Gives the entries whose ranges overlap `range`, in range order.
    #[must_use]
    pub fn overlapping(&self, range: Range) -> &[(Range, V)] {
        self.entries
            .get(self.overlap_span(range))
            .unwrap_or_default()
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
        if range.first > range.last {
            return Err(IntervalError::InvalidRange(range));
        }
        if let Some((existing, _)) = self.overlapping(range).first() {
            return Err(IntervalError::Overlap {
                new: range,
                existing: *existing,
            });
        }
        let at = self.entries.partition_point(|(r, _)| r.first < range.first);
        self.entries.insert(at, (range, value));
        Ok(())
    }

    /// Removes the entry whose range holds `x` and gives it.
    pub fn remove_at(&mut self, x: u64) -> Option<(Range, V)> {
        let i = self.index_of(x)?;
        Some(self.entries.remove(i))
    }

    /// Adds many entries. The method sorts them once and checks them once.
    ///
    /// # Errors
    ///
    /// Returns [`IntervalError`] when an entry is not valid or overlaps another entry.
    /// Then the map does not change.
    pub fn extend_sorted(&mut self, mut items: Vec<(Range, V)>) -> Result<(), IntervalError> {
        if let Some((bad, _)) = items.iter().find(|(r, _)| r.first > r.last) {
            return Err(IntervalError::InvalidRange(*bad));
        }
        items.sort_by_key(|(r, _)| *r);
        for pair in items.windows(2) {
            if let [(a, _), (b, _)] = pair
                && a.last >= b.first
            {
                return Err(IntervalError::Overlap {
                    new: *b,
                    existing: *a,
                });
            }
        }
        for (r, _) in &items {
            if let Some((existing, _)) = self.overlapping(*r).first() {
                return Err(IntervalError::Overlap {
                    new: *r,
                    existing: *existing,
                });
            }
        }
        // Items after the last entry go on the end. A caller that adds bodies in address
        // order then pays for its own items only, not for a copy of the whole map.
        let after_last = match (self.entries.last(), items.first()) {
            (Some((last, _)), Some((first, _))) => last.last < first.first,
            _ => true,
        };
        if after_last {
            self.entries.extend(items);
            return Ok(());
        }
        let old = std::mem::take(&mut self.entries);
        let mut merged = Vec::with_capacity(old.len().saturating_add(items.len()));
        let mut old = old.into_iter().peekable();
        let mut new = items.into_iter().peekable();
        loop {
            let take_old = match (old.peek(), new.peek()) {
                (Some((a, _)), Some((b, _))) => a.first < b.first,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            let next = if take_old { old.next() } else { new.next() };
            merged.extend(next);
        }
        self.entries = merged;
        Ok(())
    }

    /// Gives the mapped value nearest to `x`, or `None` for an empty map.
    ///
    /// A value in the map gives itself. For a gap, the nearer end of the two neighbor
    /// ranges wins. A tie gives the lower value.
    #[must_use]
    pub fn nearest(&self, x: u64) -> Option<u64> {
        if self.index_of(x).is_some() {
            return Some(x);
        }
        let after = self.entries.partition_point(|(r, _)| r.first <= x);
        let below = after
            .checked_sub(1)
            .and_then(|i| self.entries.get(i))
            .map(|(r, _)| r.last);
        let above = self.entries.get(after).map(|(r, _)| r.first);
        match (below, above) {
            (Some(lo), Some(hi)) if x.abs_diff(lo) <= x.abs_diff(hi) => Some(lo),
            (_, Some(hi)) => Some(hi),
            (lo, None) => lo,
        }
    }
}

impl<V: Clone> IntervalMap<V> {
    /// Removes the values in `range`. A range that is partly inside `range` splits.
    ///
    /// Each part that stays keeps a copy of the old value.
    pub fn clear_range(&mut self, range: Range) {
        let span = self.overlap_span(range);
        if span.is_empty() {
            return;
        }
        let mut keep = Vec::with_capacity(2);
        if let Some((r, v)) = self.entries.get(span.start)
            && r.first < range.first
            && let Some(last) = range.first.checked_sub(1)
        {
            keep.push((
                Range {
                    first: r.first,
                    last,
                },
                v.clone(),
            ));
        }
        if let Some((r, v)) = span.end.checked_sub(1).and_then(|i| self.entries.get(i))
            && r.last > range.last
            && let Some(first) = range.last.checked_add(1)
        {
            keep.push((
                Range {
                    first,
                    last: r.last,
                },
                v.clone(),
            ));
        }
        self.entries.splice(span, keep);
    }

    /// Sets `value` on `range`. The method first removes the old values in `range`.
    ///
    /// # Errors
    ///
    /// Returns [`IntervalError::InvalidRange`] when `first > last`.
    pub fn replace(&mut self, range: Range, value: V) -> Result<(), IntervalError> {
        if range.first > range.last {
            return Err(IntervalError::InvalidRange(range));
        }
        self.clear_range(range);
        self.insert(range, value)
    }
}
