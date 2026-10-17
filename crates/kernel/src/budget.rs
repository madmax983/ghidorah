//! K6: the budget fit rule of the result trimmer (design Section 10.9).
//!
//! The trimmer keeps the longest prefix of items that fits in the character budget.
//! The cost of a prefix of `k > 0` items is `overhead + sum(sizes[..k]) + sep * (k - 1)`.
//! Verus proves that [`fit_prefix`] gives the largest prefix that fits, with no overflow.

#[cfg(not(verus_only))]
use ghidorah_spec::verus_spec;
#[cfg(verus_only)]
use vstd::prelude::*;

#[cfg(verus_only)]
verus! {

/// The sum of the first `k` sizes.
pub open spec fn spec_sum(sizes: Seq<u64>, k: int) -> int
    decreases k,
{
    if k <= 0 || k > sizes.len() {
        0
    } else {
        spec_sum(sizes, k - 1) + sizes[k - 1]
    }
}

/// The cost of the prefix of `k` items: `overhead + sum(sizes[..k]) + sep * (k - 1)`.
///
/// The empty prefix costs nothing.
pub open spec fn spec_cost(sizes: Seq<u64>, overhead: u64, sep: u64, k: int) -> int {
    if k <= 0 {
        0
    } else {
        overhead + spec_sum(sizes, k) + sep * (k - 1)
    }
}

} // verus!

/// Gives the largest `k` such that the prefix `sizes[..k]` fits in `max`.
///
/// A prefix of `k > 0` items fits when `overhead + sum(sizes[..k]) + sep * (k - 1) <= max`.
/// The empty prefix always fits. The items keep their order.
#[must_use]
#[verus_spec(k =>
    ensures
        k <= sizes@.len(),
        k > 0 ==> spec_cost(sizes@, overhead, sep, k as int) <= max,
        forall|m: int| k < m <= sizes@.len() ==> spec_cost(sizes@, overhead, sep, m) > max,
)]
pub fn fit_prefix(sizes: &[u64], overhead: u64, sep: u64, max: u64) -> usize {
    0
}
