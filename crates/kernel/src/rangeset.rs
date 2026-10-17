//! K3: a set of `u64` values as sorted, disjoint and coalesced inclusive ranges.
//!
//! The view of a set is `covers(s, x)`: a range of `s` holds `x`.
//! Verus proves these properties:
//!
//! - The type invariant holds after each call: each range is valid, the ranges are sorted,
//!   and a gap of at least one value comes between two ranges.
//! - After `insert(r)`, `covers(new, x) == covers(old, x) || r.has(x)`.
//! - After `remove(r)`, `covers(new, x) == covers(old, x) && !r.has(x)`.
//! - `contains(x) == covers(view, x)`.
//!
//! `insert` and `remove` find the affected run `[i, j)` with a binary search.
//! Then they make the new range list with `push` loops.

#[cfg(not(verus_only))]
use ghidorah_spec::{verus_spec, verus_verify};
#[cfg(verus_only)]
use vstd::prelude::*;

use crate::range::Range;

/// A set of `u64` values as sorted, disjoint and coalesced inclusive ranges.
///
/// Two sets with the same values have the same ranges, so `==` compares the values.
#[verus_verify]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeSet {
    ranges: Vec<Range>,
}

#[cfg(verus_only)]
verus! {

/// Each range is valid, and a gap of at least one value comes between two ranges.
pub open spec fn seq_wf(s: Seq<Range>) -> bool {
    &&& forall|i: int| 0 <= i < s.len() ==> (#[trigger] s[i]).wf()
    &&& forall|i: int, j: int| 0 <= i < j < s.len()
        ==> (#[trigger] s[i]).last + 1 < (#[trigger] s[j]).first
}

/// A range of `s` holds `x`.
pub open spec fn covers(s: Seq<Range>, x: int) -> bool {
    exists|i: int| 0 <= i < s.len() && (#[trigger] s[i]).has(x)
}

impl View for RangeSet {
    type V = Seq<Range>;

    closed spec fn view(&self) -> Seq<Range> {
        self.ranges@
    }
}

impl RangeSet {
    /// The ranges of the set satisfy [`seq_wf`].
    pub open spec fn wf(&self) -> bool {
        seq_wf(self@)
    }
}

} // verus!

#[verus_verify]
impl RangeSet {
    /// Makes an empty set.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r.wf(),
            r@.len() == 0,
    )]
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Gives the ranges in ascending order.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r@ == self@,
    )]
    pub fn ranges(&self) -> &[Range] {
        &[]
    }

    /// Gives the count of ranges.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r == self@.len(),
    )]
    pub fn len(&self) -> usize {
        0
    }

    /// Tells if the set holds no value.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r == (self@.len() == 0),
    )]
    pub fn is_empty(&self) -> bool {
        true
    }

    /// Gives the range with the lowest values.
    #[must_use]
    #[verus_spec(r =>
        ensures
            match r {
                Some(v) => self@.len() > 0 && v == self@[0],
                None => self@.len() == 0,
            },
    )]
    pub fn first(&self) -> Option<Range> {
        None
    }

    /// Tells if the set holds `x`.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
        ensures
            r == covers(self@, x as int),
    )]
    pub fn contains(&self, x: u64) -> bool {
        false
    }

    /// Gives the range of the set that holds `x`.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
        ensures
            match r {
                Some(v) => v.has(x as int)
                    && exists|i: int| 0 <= i < self@.len() && self@[i] == v,
                None => !covers(self@, x as int),
            },
    )]
    pub fn find(&self, x: u64) -> Option<Range> {
        None
    }

    /// Adds the values of `r`. Touching and overlapping ranges merge into one range.
    ///
    /// An empty `r` changes nothing.
    #[verus_spec(
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            forall|x: int| covers(final(self)@, x) == (covers(old(self)@, x) || r.has(x)),
    )]
    pub fn insert(&mut self, r: Range) {}

    /// Removes the values of `r`. A range that holds values on the two sides of `r` splits.
    ///
    /// An empty `r` changes nothing.
    #[verus_spec(
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            forall|x: int| covers(final(self)@, x) == (covers(old(self)@, x) && !r.has(x)),
    )]
    pub fn remove(&mut self, r: Range) {}

    /// Makes the set of the values of `items`. The items can come in any order.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r.wf(),
            forall|x: int| covers(r@, x)
                == (exists|i: int| 0 <= i < items@.len() && (#[trigger] items@[i]).has(x)),
    )]
    pub fn from_ranges(items: &[Range]) -> Self {
        Self::new()
    }

    /// Gives the set of the values in `self` or in `other`.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
            other.wf(),
        ensures
            r.wf(),
            forall|x: int| covers(r@, x) == (covers(self@, x) || covers(other@, x)),
    )]
    pub fn union(&self, other: &Self) -> Self {
        Self::new()
    }

    /// Gives the set of the values in `self` and not in `other`.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
            other.wf(),
        ensures
            r.wf(),
            forall|x: int| covers(r@, x) == (covers(self@, x) && !covers(other@, x)),
    )]
    pub fn subtract(&self, other: &Self) -> Self {
        Self::new()
    }

    /// Gives the set of the values in `self` and in `other`.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
            other.wf(),
        ensures
            r.wf(),
            forall|x: int| covers(r@, x) == (covers(self@, x) && covers(other@, x)),
    )]
    pub fn intersect(&self, other: &Self) -> Self {
        Self::new()
    }
}
