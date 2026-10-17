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
//! Then they cut the list at the run with `split_off`, add the new ranges and append the rest.
//! So an insert at the end of the list copies no range. The code uses no `splice` and no `drain`.

#[cfg(not(verus_only))]
use ghidorah_spec::{proof, verus_spec, verus_verify};
#[cfg(verus_only)]
use vstd::prelude::*;

use crate::range::Range;

mod lemmas;

/// A set of `u64` values as sorted, disjoint and coalesced inclusive ranges.
///
/// Two sets with the same values have the same ranges, so `==` compares the values.
#[verus_verify]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RangeSet {
    ranges: Vec<Range>,
}

// Verus gives no spec to a derived `Clone` of a type that is not `Copy`, and it warns.
// This plain impl is outside the proof, so Verus does not read it.
impl Clone for RangeSet {
    fn clone(&self) -> Self {
        Self {
            ranges: self.ranges.clone(),
        }
    }
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

/// A range of `s[..k]` holds `x`.
pub open spec fn any_has(s: Seq<Range>, k: int, x: int) -> bool {
    exists|t: int| 0 <= t < k && (#[trigger] s[t]).has(x)
}

/// The list `s` with the run `s[i..j]` replaced by `mid`.
pub open spec fn spliced(s: Seq<Range>, i: int, j: int, mid: Seq<Range>) -> Seq<Range> {
    s.subrange(0, i) + mid + s.subrange(j, s.len() as int)
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
        self.ranges.as_slice()
    }

    /// Gives the count of ranges.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r == self@.len(),
    )]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Tells if the set holds no value.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r == (self@.len() == 0),
    )]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
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
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    pub fn first(&self) -> Option<Range> {
        if self.ranges.is_empty() {
            None
        } else {
            Some(self.ranges[0])
        }
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
        self.find(x).is_some()
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
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    pub fn find(&self, x: u64) -> Option<Range> {
        let s = self.ranges.as_slice();
        let i = first_last_ge(s, x);
        if i < s.len() && s[i].first <= x {
            return Some(s[i]);
        }
        proof! {
            assert forall|k: int| 0 <= k < s@.len() implies !(#[trigger] s@[k]).has(x as int) by {
                if k > i {
                    lemmas::lemma_sorted(s@, i as int, k);
                }
            }
        }
        None
    }

    /// Adds the values of `range`. Touching and overlapping ranges merge into one range.
    ///
    /// An empty `range` changes nothing.
    #[verus_spec(
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            forall|x: int| #[trigger] covers(final(self)@, x)
                == (covers(old(self)@, x) || range.has(x)),
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn insert(&mut self, range: Range) {
        if range.first > range.last {
            return;
        }
        let list = self.ranges.as_slice();
        // The run [lo, hi) holds the ranges that overlap or touch `range`.
        let lo = if range.first == 0 {
            0
        } else {
            first_last_ge(list, range.first - 1)
        };
        let hi = if range.last == u64::MAX {
            list.len()
        } else {
            first_first_gt(list, range.last + 1)
        };
        proof! {
            if hi < lo {
                assert(list@[hi as int].wf());
            }
        }
        let merged = if lo < hi {
            let head = list[lo];
            let end = list[hi - 1];
            Range {
                first: if range.first <= head.first {
                    range.first
                } else {
                    head.first
                },
                last: if range.last >= end.last {
                    range.last
                } else {
                    end.last
                },
            }
        } else {
            range
        };
        proof! {
            lemmas::lemma_insert(list@, range, lo as int, hi as int, merged);
        }
        let mut after = self.ranges.split_off(hi);
        let _ = self.ranges.split_off(lo);
        self.ranges.push(merged);
        self.ranges.append(&mut after);
        proof! {
            assert(self.ranges@ =~= spliced(old(self).ranges@, lo as int, hi as int, seq![merged]));
        }
    }

    /// Removes the values of `range`. A range with values on the two sides of `range` splits.
    ///
    /// An empty `range` changes nothing.
    #[verus_spec(
        requires
            old(self).wf(),
        ensures
            final(self).wf(),
            forall|x: int| #[trigger] covers(final(self)@, x)
                == (covers(old(self)@, x) && !range.has(x)),
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn remove(&mut self, range: Range) {
        if range.first > range.last {
            return;
        }
        let list = self.ranges.as_slice();
        // The run [lo, hi) holds the ranges that overlap `range`.
        let lo = first_last_ge(list, range.first);
        let hi = first_first_gt(list, range.last);
        proof! {
            if hi < lo {
                assert(list@[hi as int].wf());
            }
            lemmas::lemma_remove(list@, range, lo as int, hi as int);
        }
        let mut pieces = Vec::new();
        if lo < hi {
            let head = list[lo];
            if head.first < range.first {
                pieces.push(Range {
                    first: head.first,
                    last: range.first - 1,
                });
            }
            let end = list[hi - 1];
            if end.last > range.last {
                pieces.push(Range {
                    first: range.last + 1,
                    last: end.last,
                });
            }
        }
        proof! {
            assert(pieces@ =~= lemmas::left_piece(list@, range, lo as int, hi as int)
                + lemmas::right_piece(list@, range, lo as int, hi as int));
        }
        let mut after = self.ranges.split_off(hi);
        let _ = self.ranges.split_off(lo);
        self.ranges.append(&mut pieces);
        self.ranges.append(&mut after);
        proof! {
            assert(self.ranges@ =~= spliced(
                old(self).ranges@,
                lo as int,
                hi as int,
                lemmas::left_piece(old(self).ranges@, range, lo as int, hi as int)
                    + lemmas::right_piece(old(self).ranges@, range, lo as int, hi as int),
            ));
        }
    }

    /// Makes the set of the values of `items`. The items can come in any order.
    #[must_use]
    #[verus_spec(r =>
        ensures
            r.wf(),
            forall|x: int| #[trigger] covers(r@, x)
                == (exists|i: int| 0 <= i < items@.len() && (#[trigger] items@[i]).has(x)),
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn from_ranges(items: &[Range]) -> Self {
        let mut out = Self::new();
        let mut k: usize = 0;
        #[cfg_attr(verus_only, verus_spec(
            invariant
                out.wf(),
                k <= items@.len(),
                forall|x: int| #[trigger] covers(out@, x) == any_has(items@, k as int, x),
            decreases items@.len() - k,
        ))]
        while k < items.len() {
            out.insert(items[k]);
            proof! {
                assert forall|x: int| #[trigger] covers(out@, x)
                    == any_has(items@, k as int + 1, x) by {
                    if any_has(items@, k as int + 1, x) && !items@[k as int].has(x) {
                        let t = choose|t: int| 0 <= t < k + 1 && (#[trigger] items@[t]).has(x);
                        assert(any_has(items@, k as int, x));
                    }
                    if any_has(items@, k as int, x) {
                        let t = choose|t: int| 0 <= t < k && (#[trigger] items@[t]).has(x);
                        assert(any_has(items@, k as int + 1, x));
                    }
                }
            }
            k += 1;
        }
        proof! {
            assert forall|x: int| #[trigger] covers(out@, x) == (exists|i: int| 0 <= i < items@.len()
                && (#[trigger] items@[i]).has(x)) by {}
        }
        out
    }

    /// Gives the set of the values in `self` or in `other`.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
            other.wf(),
        ensures
            r.wf(),
            forall|x: int| #[trigger] covers(r@, x) == (covers(self@, x) || covers(other@, x)),
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn union(&self, other: &Self) -> Self {
        let mut out = Self::from_ranges(self.ranges.as_slice());
        let s = other.ranges.as_slice();
        let mut k: usize = 0;
        #[cfg_attr(verus_only, verus_spec(
            invariant
                out.wf(),
                k <= s@.len(),
                s@ == other@,
                forall|x: int| #[trigger] covers(out@, x)
                    == (covers(self@, x) || any_has(s@, k as int, x)),
            decreases s@.len() - k,
        ))]
        while k < s.len() {
            out.insert(s[k]);
            proof! {
                assert forall|x: int| #[trigger] covers(out@, x)
                    == (covers(self@, x) || any_has(s@, k as int + 1, x)) by {
                    if any_has(s@, k as int + 1, x) && !s@[k as int].has(x) {
                        let t = choose|t: int| 0 <= t < k + 1 && (#[trigger] s@[t]).has(x);
                        assert(any_has(s@, k as int, x));
                    }
                    if any_has(s@, k as int, x) {
                        let t = choose|t: int| 0 <= t < k && (#[trigger] s@[t]).has(x);
                        assert(any_has(s@, k as int + 1, x));
                    }
                }
            }
            k += 1;
        }
        out
    }

    /// Gives the set of the values in `self` and not in `other`.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
            other.wf(),
        ensures
            r.wf(),
            forall|x: int| #[trigger] covers(r@, x) == (covers(self@, x) && !covers(other@, x)),
    )]
    #[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
    #[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
    pub fn subtract(&self, other: &Self) -> Self {
        let mut out = Self::from_ranges(self.ranges.as_slice());
        let s = other.ranges.as_slice();
        let mut k: usize = 0;
        #[cfg_attr(verus_only, verus_spec(
            invariant
                out.wf(),
                k <= s@.len(),
                s@ == other@,
                forall|x: int| #[trigger] covers(out@, x)
                    == (covers(self@, x) && !any_has(s@, k as int, x)),
            decreases s@.len() - k,
        ))]
        while k < s.len() {
            out.remove(s[k]);
            proof! {
                assert forall|x: int| #[trigger] covers(out@, x)
                    == (covers(self@, x) && !any_has(s@, k as int + 1, x)) by {
                    if any_has(s@, k as int + 1, x) && !s@[k as int].has(x) {
                        let t = choose|t: int| 0 <= t < k + 1 && (#[trigger] s@[t]).has(x);
                        assert(any_has(s@, k as int, x));
                    }
                    if any_has(s@, k as int, x) {
                        let t = choose|t: int| 0 <= t < k && (#[trigger] s@[t]).has(x);
                        assert(any_has(s@, k as int + 1, x));
                    }
                }
            }
            k += 1;
        }
        out
    }

    /// Gives the set of the values in `self` and in `other`.
    #[must_use]
    #[verus_spec(r =>
        requires
            self.wf(),
            other.wf(),
        ensures
            r.wf(),
            forall|x: int| #[trigger] covers(r@, x) == (covers(self@, x) && covers(other@, x)),
    )]
    pub fn intersect(&self, other: &Self) -> Self {
        self.subtract(&self.subtract(other))
    }
}

/// Gives the first index `i` with `s[i].last >= x`. All earlier ranges end below `x`.
#[verus_spec(i =>
    requires
        seq_wf(s@),
    ensures
        i <= s@.len(),
        forall|k: int| 0 <= k < i ==> (#[trigger] s@[k]).last < x,
        forall|k: int| i <= k < s@.len() ==> (#[trigger] s@[k]).last >= x,
)]
#[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
#[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
fn first_last_ge(s: &[Range], x: u64) -> usize {
    let mut lo: usize = 0;
    let mut hi: usize = s.len();
    #[cfg_attr(verus_only, verus_spec(
        invariant
            lo <= hi <= s@.len(),
            seq_wf(s@),
            forall|k: int| 0 <= k < lo ==> (#[trigger] s@[k]).last < x,
            forall|k: int| hi <= k < s@.len() ==> (#[trigger] s@[k]).last >= x,
        decreases hi - lo,
    ))]
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if s[mid].last < x {
            proof! {
                assert forall|k: int| 0 <= k <= mid implies (#[trigger] s@[k]).last < x by {
                    lemmas::lemma_sorted(s@, k, mid as int);
                }
            }
            lo = mid + 1;
        } else {
            proof! {
                assert forall|k: int| mid <= k < s@.len() implies (#[trigger] s@[k]).last >= x by {
                    lemmas::lemma_sorted(s@, mid as int, k);
                }
            }
            hi = mid;
        }
    }
    lo
}

/// Gives the first index `j` with `s[j].first > x`. All earlier ranges start at or below `x`.
#[verus_spec(j =>
    requires
        seq_wf(s@),
    ensures
        j <= s@.len(),
        forall|k: int| 0 <= k < j ==> (#[trigger] s@[k]).first <= x,
        forall|k: int| j <= k < s@.len() ==> (#[trigger] s@[k]).first > x,
)]
#[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
#[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
fn first_first_gt(s: &[Range], x: u64) -> usize {
    let mut lo: usize = 0;
    let mut hi: usize = s.len();
    #[cfg_attr(verus_only, verus_spec(
        invariant
            lo <= hi <= s@.len(),
            seq_wf(s@),
            forall|k: int| 0 <= k < lo ==> (#[trigger] s@[k]).first <= x,
            forall|k: int| hi <= k < s@.len() ==> (#[trigger] s@[k]).first > x,
        decreases hi - lo,
    ))]
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if s[mid].first <= x {
            proof! {
                assert forall|k: int| 0 <= k <= mid implies (#[trigger] s@[k]).first <= x by {
                    lemmas::lemma_sorted(s@, k, mid as int);
                }
            }
            lo = mid + 1;
        } else {
            proof! {
                assert forall|k: int| mid <= k < s@.len() implies (#[trigger] s@[k]).first > x by {
                    lemmas::lemma_sorted(s@, mid as int, k);
                }
            }
            hi = mid;
        }
    }
    lo
}
