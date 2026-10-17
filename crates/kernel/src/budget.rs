//! K6: the budget fit rule of the result trimmer (design Section 10.9).
//!
//! The trimmer keeps the longest prefix of items that fits in the character budget.
//! The cost of a prefix of `k > 0` items is `overhead + sum(sizes[..k]) + sep * (k - 1)`.
//! Verus proves that [`fit_prefix`] gives the largest prefix that fits, with no overflow.

#[cfg(not(verus_only))]
use ghidorah_spec::{proof, verus_spec};
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

/// One more item adds its size, and a separator after the first item.
pub proof fn lemma_cost_step(sizes: Seq<u64>, overhead: u64, sep: u64, k: int)
    requires
        0 <= k < sizes.len(),
    ensures
        k == 0 ==> spec_cost(sizes, overhead, sep, k + 1) == overhead + sizes[0],
        k > 0 ==> spec_cost(sizes, overhead, sep, k + 1)
            == spec_cost(sizes, overhead, sep, k) + sep + sizes[k],
{
    assert(spec_sum(sizes, k + 1) == spec_sum(sizes, k) + sizes[k]);
    if k > 0 {
        assert(sep * k == sep * (k - 1) + sep) by (nonlinear_arith);
    }
}

/// The cost of a prefix of at least one item never falls when the prefix grows.
pub proof fn lemma_cost_mono(sizes: Seq<u64>, overhead: u64, sep: u64, a: int, b: int)
    requires
        1 <= a <= b <= sizes.len(),
    ensures
        spec_cost(sizes, overhead, sep, a) <= spec_cost(sizes, overhead, sep, b),
    decreases b - a,
{
    if a < b {
        lemma_cost_mono(sizes, overhead, sep, a, b - 1);
        lemma_cost_step(sizes, overhead, sep, b - 1);
    }
}

/// Each prefix of at least `a` items costs at least the prefix of `a` items.
pub proof fn lemma_cost_grows(sizes: Seq<u64>, overhead: u64, sep: u64, a: int)
    requires
        1 <= a,
    ensures
        forall|m: int| a <= m <= sizes.len()
            ==> spec_cost(sizes, overhead, sep, a) <= #[trigger] spec_cost(sizes, overhead, sep, m),
{
    assert forall|m: int| a <= m <= sizes.len() implies spec_cost(sizes, overhead, sep, a)
        <= #[trigger] spec_cost(sizes, overhead, sep, m) by {
        lemma_cost_mono(sizes, overhead, sep, a, m);
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
#[expect(clippy::indexing_slicing, reason = "bound proved by Verus")]
#[expect(clippy::arithmetic_side_effects, reason = "bound proved by Verus")]
pub fn fit_prefix(sizes: &[u64], overhead: u64, sep: u64, max: u64) -> usize {
    let n = sizes.len();
    let mut k: usize = 0;
    let mut cost: u64 = 0;
    #[cfg_attr(verus_only, verus_spec(
        invariant
            k <= n,
            n == sizes@.len(),
            cost as int == spec_cost(sizes@, overhead, sep, k as int),
            k > 0 ==> cost <= max,
        decreases n - k,
    ))]
    while k < n {
        // The cost of the next prefix: the first item adds no separator.
        let base = if k == 0 {
            Some(overhead)
        } else {
            cost.checked_add(sep)
        };
        let next = match base {
            Some(b) => b.checked_add(sizes[k]),
            None => None,
        };
        proof! {
            lemma_cost_step(sizes@, overhead, sep, k as int);
        }
        match next {
            Some(c) if c <= max => {
                cost = c;
                k += 1;
            }
            _ => {
                proof! {
                    lemma_cost_grows(sizes@, overhead, sep, k as int + 1);
                }
                return k;
            }
        }
    }
    k
}
