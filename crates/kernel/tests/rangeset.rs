//! K3 tier-1 tests: examples and the `BTreeSet<u64>` model test (AC-030, AC-036).

use std::collections::BTreeSet;

use ghidorah_kernel::{Range, RangeSet};
use ghidorah_testkit::model::{Settings, model_check};
use ghidorah_testkit::pbt::Gen;

const MAX: u64 = u64::MAX;

fn r(first: u64, last: u64) -> Range {
    Range { first, last }
}

fn set(items: &[(u64, u64)]) -> RangeSet {
    let items: Vec<Range> = items.iter().map(|&(a, b)| r(a, b)).collect();
    RangeSet::from_ranges(&items)
}

fn pairs(s: &RangeSet) -> Vec<(u64, u64)> {
    s.ranges().iter().map(|x| (x.first, x.last)).collect()
}

/// Checks the invariant: valid ranges, sorted, and a gap of at least one value between two ranges.
fn assert_wf(s: &RangeSet) {
    let ranges = s.ranges();
    for x in ranges {
        assert!(x.first <= x.last, "{ranges:?}");
    }
    for w in ranges.windows(2) {
        assert!(w[0].last < MAX && w[0].last + 1 < w[1].first, "{ranges:?}");
    }
    assert_eq!(s.len(), ranges.len());
    assert_eq!(s.is_empty(), ranges.is_empty());
}

#[test]
fn k3_insert_coalesces() {
    let mut s = RangeSet::new();
    s.insert(r(10, 20));
    s.insert(r(30, 40));
    assert_eq!(pairs(&s), [(10, 20), (30, 40)]);
    s.insert(r(21, 29));
    assert_eq!(pairs(&s), [(10, 40)], "touching ranges merge");
    s.insert(r(0, 8));
    s.insert(r(50, 60));
    s.insert(r(9, 9));
    assert_eq!(pairs(&s), [(0, 40), (50, 60)]);
    s.insert(r(5, 55));
    assert_eq!(pairs(&s), [(0, 60)]);
    s.insert(r(MAX, MAX));
    s.insert(r(MAX - 5, MAX - 1));
    assert_eq!(pairs(&s), [(0, 60), (MAX - 5, MAX)]);
    s.insert(r(7, 3));
    assert_eq!(
        pairs(&s),
        [(0, 60), (MAX - 5, MAX)],
        "an empty range changes nothing"
    );
    s.insert(r(0, MAX));
    assert_eq!(pairs(&s), [(0, MAX)]);
    assert_wf(&s);
}

#[test]
fn k3_remove_splits() {
    let mut s = set(&[(0, 100)]);
    s.remove(r(10, 20));
    assert_eq!(pairs(&s), [(0, 9), (21, 100)]);
    s.remove(r(0, 0));
    s.remove(r(100, 200));
    assert_eq!(pairs(&s), [(1, 9), (21, 99)]);
    s.remove(r(5, 30));
    assert_eq!(pairs(&s), [(1, 4), (31, 99)]);
    s.remove(r(9, 3));
    assert_eq!(
        pairs(&s),
        [(1, 4), (31, 99)],
        "an empty range changes nothing"
    );
    s.remove(r(0, MAX));
    assert!(s.is_empty());
    let mut top = set(&[(MAX - 10, MAX)]);
    top.remove(r(MAX, MAX));
    assert_eq!(pairs(&top), [(MAX - 10, MAX - 1)]);
    top.remove(r(MAX - 10, MAX - 10));
    assert_eq!(pairs(&top), [(MAX - 9, MAX - 1)]);
    assert_wf(&top);
}

#[test]
fn k3_queries_and_set_ops() {
    let a = set(&[(30, 40), (0, 10), (11, 12), (MAX - 1, MAX)]);
    assert_eq!(pairs(&a), [(0, 12), (30, 40), (MAX - 1, MAX)]);
    assert_eq!(a.first(), Some(r(0, 12)));
    assert_eq!(RangeSet::new().first(), None);
    assert!(a.contains(12) && !a.contains(13) && a.contains(MAX));
    assert_eq!(a.find(35), Some(r(30, 40)));
    assert_eq!(a.find(29), None);
    let b = set(&[(5, 35), (MAX, MAX)]);
    assert_eq!(pairs(&a.union(&b)), [(0, 40), (MAX - 1, MAX)]);
    assert_eq!(pairs(&a.intersect(&b)), [(5, 12), (30, 35), (MAX, MAX)]);
    assert_eq!(
        pairs(&a.subtract(&b)),
        [(0, 4), (36, 40), (MAX - 1, MAX - 1)]
    );
    assert_eq!(a.union(&RangeSet::new()), a);
    assert!(a.intersect(&RangeSet::new()).is_empty());
    assert_eq!(
        set(&[(1, 2), (3, 4)]),
        set(&[(1, 4)]),
        "equal values give equal sets"
    );
}

/// One operation of the model test. Values are indexes into the test universe.
#[derive(Debug, Clone)]
enum Op {
    Insert(u64, u64),
    Remove(u64, u64),
    Contains(u64),
    Find(u64),
    First,
    Union(Vec<(u64, u64)>),
    Intersect(Vec<(u64, u64)>),
    Subtract(Vec<(u64, u64)>),
}

/// The observation after one operation: the query result and the full range list.
type Seen = (Option<(u64, u64)>, Vec<(u64, u64)>);

/// The test universe: 0..256 and the 256 values up to `u64::MAX`.
fn value(index: u64) -> u64 {
    if index < 256 {
        index
    } else {
        MAX - 511 + index
    }
}

/// Draws a range of indexes inside one half of the universe.
fn gen_pair(g: &mut Gen) -> (u64, u64) {
    let base = if g.bool() { 0 } else { 256 };
    let a = base + g.draw(256);
    let b = base + g.draw(256);
    if g.draw(16) == 0 {
        (b.max(a), b.min(a))
    } else {
        (a.min(b), a.max(b))
    }
}

fn gen_op(g: &mut Gen) -> Op {
    match g.draw(10) {
        0 | 1 | 2 => {
            let (a, b) = gen_pair(g);
            Op::Insert(a, b)
        }
        3 | 4 => {
            let (a, b) = gen_pair(g);
            Op::Remove(a, b)
        }
        5 => Op::Contains(g.draw(512)),
        6 => Op::Find(g.draw(512)),
        7 => {
            if g.bool() {
                Op::First
            } else {
                Op::Union(g.vec(4, gen_pair))
            }
        }
        8 => Op::Intersect(g.vec(4, gen_pair)),
        _ => Op::Subtract(g.vec(4, gen_pair)),
    }
}

fn to_range((a, b): (u64, u64)) -> Range {
    r(value(a), value(b))
}

fn sut_set(items: &[(u64, u64)]) -> RangeSet {
    let ranges: Vec<Range> = items.iter().copied().map(to_range).collect();
    RangeSet::from_ranges(&ranges)
}

fn sut_apply(s: &mut RangeSet, op: &Op) -> Seen {
    let query = match op {
        Op::Insert(a, b) => {
            s.insert(to_range((*a, *b)));
            None
        }
        Op::Remove(a, b) => {
            s.remove(to_range((*a, *b)));
            None
        }
        Op::Contains(x) => Some((u64::from(s.contains(value(*x))), 0)),
        Op::Find(x) => s.find(value(*x)).map(|f| (f.first, f.last)),
        Op::First => s.first().map(|f| (f.first, f.last)),
        Op::Union(items) => {
            *s = s.union(&sut_set(items));
            None
        }
        Op::Intersect(items) => {
            *s = s.intersect(&sut_set(items));
            None
        }
        Op::Subtract(items) => {
            *s = s.subtract(&sut_set(items));
            None
        }
    };
    assert_wf(s);
    (query, pairs(s))
}

fn model_insert(m: &mut BTreeSet<u64>, (a, b): (u64, u64)) {
    if a <= b {
        m.extend((a..=b).map(value));
    }
}

fn model_set(items: &[(u64, u64)]) -> BTreeSet<u64> {
    let mut m = BTreeSet::new();
    for &pair in items {
        model_insert(&mut m, pair);
    }
    m
}

/// Gives the coalesced ranges of a model set.
fn model_ranges(m: &BTreeSet<u64>) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &x in m {
        match out.last_mut() {
            Some(last) if last.1 + 1 == x => last.1 = x,
            _ => out.push((x, x)),
        }
    }
    out
}

fn model_apply(m: &mut BTreeSet<u64>, op: &Op) -> Seen {
    let query = match op {
        Op::Insert(a, b) => {
            model_insert(m, (*a, *b));
            None
        }
        Op::Remove(a, b) => {
            if a <= b {
                for i in *a..=*b {
                    m.remove(&value(i));
                }
            }
            None
        }
        Op::Contains(x) => Some((u64::from(m.contains(&value(*x))), 0)),
        Op::Find(x) => {
            let x = value(*x);
            model_ranges(m).into_iter().find(|&(a, b)| a <= x && x <= b)
        }
        Op::First => model_ranges(m).first().copied(),
        Op::Union(items) => {
            m.extend(model_set(items));
            None
        }
        Op::Intersect(items) => {
            let other = model_set(items);
            m.retain(|x| other.contains(x));
            None
        }
        Op::Subtract(items) => {
            let other = model_set(items);
            m.retain(|x| !other.contains(x));
            None
        }
    };
    (query, model_ranges(m))
}

#[test]
fn ac_036_rangeset_model() {
    model_check(
        "ac_036_rangeset_model",
        Settings {
            cases: 10_000,
            max_steps: 16,
        },
        || (RangeSet::new(), BTreeSet::new()),
        gen_op,
        sut_apply,
        model_apply,
    );
}
