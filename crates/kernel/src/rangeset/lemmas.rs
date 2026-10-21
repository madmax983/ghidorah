//! The proof lemmas of K3. Plain builds compile this module to nothing.

#[cfg(verus_only)]
use vstd::prelude::*;

#[cfg(verus_only)]
verus! {

use super::{any_has, covers, seq_wf, spliced};
use crate::range::Range;

/// The order facts of a valid range list.
pub proof fn lemma_sorted(s: Seq<Range>, a: int, b: int)
    requires
        seq_wf(s),
        0 <= a <= b < s.len(),
    ensures
        s[a].first <= s[b].first,
        s[a].last <= s[b].last,
        a < b ==> s[a].last + 1 < s[b].first,
{
    assert(s[a].wf() && s[b].wf());
}

/// The index map of `spliced(s, i, j, mid)`.
pub proof fn lemma_spliced_index(s: Seq<Range>, i: int, j: int, mid: Seq<Range>)
    requires
        0 <= i <= j <= s.len(),
    ensures
        spliced(s, i, j, mid).len() == i + mid.len() + s.len() - j,
        forall|k: int| 0 <= k < i ==> #[trigger] spliced(s, i, j, mid)[k] == s[k],
        forall|k: int| 0 <= k < mid.len() ==> #[trigger] spliced(s, i, j, mid)[i + k] == mid[k],
        forall|k: int| j <= k < s.len()
            ==> #[trigger] spliced(s, i, j, mid)[k - j + i + mid.len()] == s[k],
{
    let t = spliced(s, i, j, mid);
    assert forall|k: int| 0 <= k < i implies #[trigger] t[k] == s[k] by {}
    assert forall|k: int| 0 <= k < mid.len() implies #[trigger] t[i + k] == mid[k] by {}
    assert forall|k: int| j <= k < s.len() implies #[trigger] t[k - j + i + mid.len()] == s[k] by {}
}

/// A splice of a valid run between two valid parts gives a valid list.
///
/// The run `mid` must have a gap after `s[i - 1]` and before `s[j]`.
pub proof fn lemma_splice_wf(s: Seq<Range>, i: int, j: int, mid: Seq<Range>)
    requires
        seq_wf(s),
        seq_wf(mid),
        0 <= i <= j <= s.len(),
        i > 0 && mid.len() > 0 ==> s[i - 1].last + 1 < mid[0].first,
        j < s.len() && mid.len() > 0 ==> mid[mid.len() - 1].last + 1 < s[j].first,
    ensures
        seq_wf(spliced(s, i, j, mid)),
{
    let t = spliced(s, i, j, mid);
    let p = i + mid.len();
    lemma_spliced_index(s, i, j, mid);
    assert forall|k: int| 0 <= k < t.len() implies (#[trigger] t[k]).wf() by {
        if k < i {
            assert(t[k] == s[k]);
        } else if k < p {
            assert(t[i + (k - i)] == mid[k - i]);
        } else {
            assert(t[(k - p + j) - j + i + mid.len()] == s[k - p + j]);
        }
    }
    assert forall|a: int, b: int| 0 <= a < b < t.len() implies (#[trigger] t[a]).last + 1 < (
    #[trigger] t[b]).first by {
        if b < i {
            assert(t[a] == s[a] && t[b] == s[b]);
        } else if b < p {
            let bm = b - i;
            assert(t[i + bm] == mid[bm]);
            if a < i {
                assert(t[a] == s[a]);
                lemma_sorted(s, a, i - 1);
                lemma_sorted(mid, 0, bm);
            } else {
                assert(t[i + (a - i)] == mid[a - i]);
            }
        } else {
            let bs = b - p + j;
            assert(t[bs - j + i + mid.len()] == s[bs]);
            if a < i {
                assert(t[a] == s[a]);
                lemma_sorted(s, a, bs);
            } else if a < p {
                let am = a - i;
                assert(t[i + am] == mid[am]);
                lemma_sorted(mid, am, mid.len() - 1);
                lemma_sorted(s, j, bs);
            } else {
                let as_ = a - p + j;
                assert(t[as_ - j + i + mid.len()] == s[as_]);
                lemma_sorted(s, as_, bs);
            }
        }
    }
}

/// The values of a splice are the values of its three parts.
pub proof fn lemma_splice_covers(s: Seq<Range>, i: int, j: int, mid: Seq<Range>, x: int)
    requires
        0 <= i <= j <= s.len(),
    ensures
        covers(spliced(s, i, j, mid), x) == (any_has(s, i, x) || covers(mid, x) || exists|k: int|
            j <= k < s.len() && (#[trigger] s[k]).has(x)),
{
    let t = spliced(s, i, j, mid);
    let p = i + mid.len();
    lemma_spliced_index(s, i, j, mid);
    if covers(t, x) {
        let k = choose|k: int| 0 <= k < t.len() && (#[trigger] t[k]).has(x);
        if k < i {
            assert(t[k] == s[k]);
        } else if k < p {
            assert(t[i + (k - i)] == mid[k - i]);
        } else {
            assert(t[(k - p + j) - j + i + mid.len()] == s[k - p + j]);
        }
    }
    if any_has(s, i, x) {
        let k = choose|k: int| 0 <= k < i && (#[trigger] s[k]).has(x);
        assert(t[k] == s[k]);
    }
    if covers(mid, x) {
        let k = choose|k: int| 0 <= k < mid.len() && (#[trigger] mid[k]).has(x);
        assert(t[i + k] == mid[k]);
    }
    if exists|k: int| j <= k < s.len() && (#[trigger] s[k]).has(x) {
        let k = choose|k: int| j <= k < s.len() && (#[trigger] s[k]).has(x);
        assert(t[k - j + i + mid.len()] == s[k]);
    }
}

/// The result list of `insert`: the merged range `m` replaces the run `s[i..j]`.
pub proof fn lemma_insert(s: Seq<Range>, r: Range, i: int, j: int, m: Range)
    requires
        seq_wf(s),
        r.wf(),
        0 <= i <= j <= s.len(),
        forall|k: int| 0 <= k < i ==> (#[trigger] s[k]).last + 1 < r.first,
        forall|k: int| i <= k < s.len() ==> (#[trigger] s[k]).last + 1 >= r.first,
        forall|k: int| 0 <= k < j ==> (#[trigger] s[k]).first <= r.last + 1,
        forall|k: int| j <= k < s.len() ==> (#[trigger] s[k]).first > r.last + 1,
        i == j ==> m == r,
        i < j ==> m.first == (if r.first <= s[i].first { r.first } else { s[i].first }),
        i < j ==> m.last == (if r.last >= s[j - 1].last { r.last } else { s[j - 1].last }),
    ensures
        seq_wf(spliced(s, i, j, seq![m])),
        forall|x: int| #[trigger] covers(spliced(s, i, j, seq![m]), x) == (covers(s, x) || r.has(x)),
{
    let mid = seq![m];
    assert(mid[0] == m);
    if i > 0 && i < j {
        lemma_sorted(s, i - 1, i);
    }
    if j < s.len() && i < j {
        lemma_sorted(s, j - 1, j);
    }
    lemma_splice_wf(s, i, j, mid);
    assert forall|x: int| #[trigger] covers(spliced(s, i, j, mid), x) == (covers(s, x) || r.has(x))
        by {
        lemma_splice_covers(s, i, j, mid, x);
        if covers(mid, x) && !r.has(x) && i < j {
            if x < r.first {
                assert(s[i].has(x));
            } else {
                assert(s[j - 1].has(x));
            }
        }
        if r.has(x) {
            assert(mid[0].has(x));
        }
        if covers(s, x) {
            let k = choose|k: int| 0 <= k < s.len() && (#[trigger] s[k]).has(x);
            if i <= k < j {
                lemma_sorted(s, i, k);
                lemma_sorted(s, k, j - 1);
                assert(mid[0].has(x));
            }
        }
    }
}

/// The left piece of a remove: the values of `s[i]` below `r`.
pub open spec fn left_piece(s: Seq<Range>, r: Range, i: int, j: int) -> Seq<Range> {
    if i < j && s[i].first < r.first {
        seq![Range { first: s[i].first, last: (r.first - 1) as u64 }]
    } else {
        Seq::empty()
    }
}

/// The right piece of a remove: the values of `s[j - 1]` above `r`.
pub open spec fn right_piece(s: Seq<Range>, r: Range, i: int, j: int) -> Seq<Range> {
    if i < j && s[j - 1].last > r.last {
        seq![Range { first: (r.last + 1) as u64, last: s[j - 1].last }]
    } else {
        Seq::empty()
    }
}

/// The result list of `remove`: the pieces outside `r` replace the run `s[i..j]`.
pub proof fn lemma_remove(s: Seq<Range>, r: Range, i: int, j: int)
    requires
        seq_wf(s),
        r.wf(),
        0 <= i <= j <= s.len(),
        forall|k: int| 0 <= k < i ==> (#[trigger] s[k]).last < r.first,
        forall|k: int| i <= k < s.len() ==> (#[trigger] s[k]).last >= r.first,
        forall|k: int| 0 <= k < j ==> (#[trigger] s[k]).first <= r.last,
        forall|k: int| j <= k < s.len() ==> (#[trigger] s[k]).first > r.last,
    ensures
        ({
            let mid = left_piece(s, r, i, j) + right_piece(s, r, i, j);
            &&& seq_wf(spliced(s, i, j, mid))
            &&& forall|x: int| #[trigger] covers(spliced(s, i, j, mid), x)
                == (covers(s, x) && !r.has(x))
        }),
{
    let lp = left_piece(s, r, i, j);
    let rp = right_piece(s, r, i, j);
    let mid = lp + rp;
    assert(mid.len() == lp.len() + rp.len());
    if lp.len() > 0 {
        assert(mid[0] == lp[0]);
    }
    if rp.len() > 0 {
        assert(mid[mid.len() - 1] == rp[0]);
    }
    if lp.len() > 0 && rp.len() > 0 {
        assert(mid[1] == rp[0]);
    }
    assert(seq_wf(mid));
    if i > 0 && i < j {
        lemma_sorted(s, i - 1, i);
    }
    if j < s.len() && i < j {
        lemma_sorted(s, j - 1, j);
    }
    if i > 0 && j < s.len() && mid.len() > 0 {
        lemma_sorted(s, i - 1, j);
    }
    lemma_splice_wf(s, i, j, mid);
    assert forall|x: int| #[trigger] covers(spliced(s, i, j, mid), x) == (covers(s, x)
        && !r.has(x)) by {
        lemma_splice_covers(s, i, j, mid, x);
        if covers(mid, x) {
            let k = choose|k: int| 0 <= k < mid.len() && (#[trigger] mid[k]).has(x);
            if lp.len() > 0 && k == 0 {
                assert(s[i].has(x));
            } else {
                assert(s[j - 1].has(x));
            }
        }
        if any_has(s, i, x) {
            let k = choose|k: int| 0 <= k < i && (#[trigger] s[k]).has(x);
            assert(s[k].has(x));
        }
        if covers(s, x) && !r.has(x) {
            let k = choose|k: int| 0 <= k < s.len() && (#[trigger] s[k]).has(x);
            if k < i {
                assert(any_has(s, i, x));
            } else if i <= k < j {
                if x < r.first {
                    if k > i {
                        lemma_sorted(s, i, k);
                    }
                    assert(mid[0].has(x));
                } else {
                    if k < j - 1 {
                        lemma_sorted(s, k, j - 1);
                    }
                    assert(mid[mid.len() - 1].has(x));
                }
            }
        }
    }
}

} // verus!
