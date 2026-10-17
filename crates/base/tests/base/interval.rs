//! Tests of `IntervalMap` (design Section 3.2, AC-037).

use ghidorah_base::{IntervalError, IntervalMap, Range};
use ghidorah_testkit::model::{Settings, model_check};
use ghidorah_testkit::pbt::Gen;

/// The model universe: 64 values at the bottom and 64 values at the top of `u64`.
const WINDOW: u64 = 64;

/// Gives the address of model cell `i`.
fn addr(i: u64) -> u64 {
    if i < WINDOW {
        i
    } else {
        u64::MAX - (2 * WINDOW - 1 - i)
    }
}

/// Gives the model cell of an address in the universe.
fn cell(x: u64) -> Option<usize> {
    if x < WINDOW {
        usize::try_from(x).ok()
    } else if x >= u64::MAX - (WINDOW - 1) {
        usize::try_from(2 * WINDOW - 1 - (u64::MAX - x)).ok()
    } else {
        None
    }
}

/// Draws a range inside one window.
fn range(g: &mut Gen) -> Range {
    let base = if g.bool() { 0 } else { WINDOW };
    let a = base + g.draw(WINDOW);
    let b = base + g.draw(WINDOW);
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    Range {
        first: addr(lo),
        last: addr(hi),
    }
}

#[derive(Debug, Clone)]
enum Op {
    Insert(Range, u8),
    Replace(Range, u8),
    Clear(Range),
    RemoveAt(u64),
    Extend(Vec<(Range, u8)>),
    Nearest(u64),
}

fn gen_op(g: &mut Gen) -> Op {
    let point = addr(g.draw(2 * WINDOW));
    match g.draw(6) {
        0 => Op::Insert(range(g), g.u8()),
        1 => Op::Replace(range(g), g.u8()),
        2 => Op::Clear(range(g)),
        3 => Op::RemoveAt(point),
        4 => Op::Extend(g.vec(4, |g| (range(g), g.u8()))),
        _ => Op::Nearest(point),
    }
}

/// The model: one cell per universe value. A cell holds the value and the tag of its entry.
///
/// Each new entry gets a new tag. So a run of cells with one tag is one SUT entry.
#[derive(Debug, Clone)]
struct Model {
    cells: Vec<Option<(u8, u32)>>,
    next_tag: u32,
}

/// The observation after one operation: the result and every cell.
type Obs = (Option<String>, Vec<Option<u8>>);

fn cells_of(r: Range) -> std::ops::RangeInclusive<usize> {
    let lo = cell(r.first).unwrap_or(0);
    let hi = cell(r.last).unwrap_or(0);
    lo..=hi
}

impl Model {
    fn new() -> Self {
        Self {
            cells: vec![None; 128],
            next_tag: 0,
        }
    }

    fn tag(&mut self) -> u32 {
        self.next_tag += 1;
        self.next_tag
    }

    fn values(&self) -> Vec<Option<u8>> {
        self.cells.iter().map(|c| c.map(|(v, _)| v)).collect()
    }

    fn fill(cells: &mut [Option<(u8, u32)>], r: Range, v: u8, tag: u32) {
        for i in cells_of(r) {
            cells[i] = Some((v, tag));
        }
    }

    fn remove_run(&mut self, i: usize) -> bool {
        let Some((_, tag)) = self.cells[i] else {
            return false;
        };
        let same = |c: &Option<(u8, u32)>| c.is_some_and(|(_, t)| t == tag);
        let mut lo = i;
        while lo > 0 && same(&self.cells[lo - 1]) {
            lo -= 1;
        }
        let mut hi = i;
        while hi + 1 < self.cells.len() && same(&self.cells[hi + 1]) {
            hi += 1;
        }
        for c in &mut self.cells[lo..=hi] {
            *c = None;
        }
        true
    }

    fn nearest(&self, x: u64) -> Option<u64> {
        (0..self.cells.len())
            .filter(|&j| self.cells[j].is_some())
            .map(|j| addr(j as u64))
            .min_by_key(|&a| (a.abs_diff(x), a))
    }
}

fn model_apply(model: &mut Model, op: &Op) -> Obs {
    let result = match op {
        Op::Insert(r, v) => {
            let free = cells_of(*r).all(|i| model.cells[i].is_none());
            if free {
                let tag = model.tag();
                Model::fill(&mut model.cells, *r, *v, tag);
            }
            Some(format!("ok={free}"))
        }
        Op::Replace(r, v) => {
            let tag = model.tag();
            Model::fill(&mut model.cells, *r, *v, tag);
            Some("ok=true".to_string())
        }
        Op::Clear(r) => {
            for i in cells_of(*r) {
                model.cells[i] = None;
            }
            None
        }
        Op::RemoveAt(x) => {
            let removed = model.remove_run(cell(*x).unwrap_or(0));
            Some(format!("removed={removed}"))
        }
        Op::Extend(items) => {
            let mut scratch = model.cells.clone();
            let mut ok = true;
            for (r, v) in items {
                if cells_of(*r).any(|i| scratch[i].is_some()) {
                    ok = false;
                }
                let tag = model.tag();
                Model::fill(&mut scratch, *r, *v, tag);
            }
            if ok {
                model.cells = scratch;
            }
            Some(format!("ok={ok}"))
        }
        Op::Nearest(x) => Some(format!("nearest={:?}", model.nearest(*x))),
    };
    (result, model.values())
}

fn observe(map: &IntervalMap<u8>) -> Vec<Option<u8>> {
    (0..2 * WINDOW).map(|i| map.get(addr(i)).copied()).collect()
}

fn sut_apply(map: &mut IntervalMap<u8>, op: &Op) -> Obs {
    let result = match op {
        Op::Insert(r, v) => Some(format!("ok={}", map.insert(*r, *v).is_ok())),
        Op::Replace(r, v) => Some(format!("ok={}", map.replace(*r, *v).is_ok())),
        Op::Clear(r) => {
            map.clear_range(*r);
            None
        }
        Op::RemoveAt(x) => Some(format!("removed={}", map.remove_at(*x).is_some())),
        Op::Extend(items) => Some(format!("ok={}", map.extend_sorted(items.clone()).is_ok())),
        Op::Nearest(x) => Some(format!("nearest={:?}", map.nearest(*x))),
    };
    let slice = map.as_slice();
    let sorted = slice.windows(2).all(|w| w[0].0.last < w[1].0.first);
    let valid = slice.iter().all(|(r, _)| r.first <= r.last);
    assert!(sorted && valid, "entries are valid, sorted and disjoint: {slice:?}");
    (result, observe(map))
}

#[test]
fn ac_037_intervalmap_model() {
    model_check(
        "ac_037_intervalmap_model",
        Settings {
            cases: 2000,
            max_steps: 40,
        },
        || (IntervalMap::new(), Model::new()),
        gen_op,
        sut_apply,
        model_apply,
    );
}

#[test]
fn intervalmap_remove_at_removes_one_entry() {
    let mut map = IntervalMap::new();
    map.insert(Range { first: 0, last: 9 }, 'a').unwrap();
    map.insert(Range { first: 10, last: 19 }, 'a').unwrap();
    assert_eq!(map.remove_at(5), Some((Range { first: 0, last: 9 }, 'a')));
    assert_eq!(map.get(5), None);
    assert_eq!(map.get(10), Some(&'a'));
    assert_eq!(map.remove_at(5), None);
    assert_eq!(map.len(), 1);
}

#[test]
fn intervalmap_boundaries() {
    let mut map = IntervalMap::new();
    let top = Range {
        first: u64::MAX - 3,
        last: u64::MAX,
    };
    let all = Range {
        first: 0,
        last: u64::MAX,
    };
    assert!(map.is_empty());
    assert_eq!(map.nearest(5), None);
    map.insert(top, 1u8).unwrap();
    assert_eq!(map.get(u64::MAX), Some(&1));
    assert_eq!(map.find(u64::MAX - 3), Some((top, &1)));
    assert_eq!(map.get(u64::MAX - 4), None);
    assert_eq!(
        map.insert(all, 2),
        Err(IntervalError::Overlap {
            new: all,
            existing: top,
        })
    );
    let bad = Range { first: 5, last: 4 };
    assert_eq!(map.insert(bad, 2), Err(IntervalError::InvalidRange(bad)));
    assert_eq!(map.replace(bad, 2), Err(IntervalError::InvalidRange(bad)));
    map.insert(Range { first: 0, last: 0 }, 3).unwrap();
    assert_eq!(map.nearest(1), Some(0));
    assert_eq!(map.nearest(u64::MAX - 10), Some(u64::MAX - 3));
    assert_eq!(map.nearest(u64::MAX), Some(u64::MAX));
    assert_eq!(map.overlapping(all).len(), 2);
    assert!(!map.is_free(all));
    assert!(map.is_free(Range { first: 1, last: 100 }));
    if let Some(v) = map.get_mut(0) {
        *v = 9;
    }
    assert_eq!(map.get(0), Some(&9));
    assert_eq!(map.iter().count(), 2);
    map.replace(all, 7).unwrap();
    assert_eq!(map.as_slice(), &[(all, 7)]);
    map.clear_range(Range {
        first: 1,
        last: u64::MAX - 1,
    });
    assert_eq!(
        map.as_slice(),
        &[(Range { first: 0, last: 0 }, 7), (Range::single(u64::MAX), 7)]
    );
    assert_eq!(IntervalMap::<u8>::default(), IntervalMap::new());
}

#[test]
fn intervalmap_extend_sorted() {
    let mut map = IntervalMap::new();
    map.insert(Range { first: 100, last: 199 }, 'm').unwrap();
    let items = vec![
        (Range { first: 300, last: 399 }, 'c'),
        (Range { first: 0, last: 99 }, 'a'),
        (Range { first: 200, last: 299 }, 'b'),
    ];
    map.extend_sorted(items).unwrap();
    let firsts: Vec<u64> = map.iter().map(|(r, _)| r.first).collect();
    assert_eq!(firsts, [0, 100, 200, 300]);
    let before = map.clone();
    let clash = vec![
        (Range { first: 400, last: 499 }, 'x'),
        (Range { first: 450, last: 460 }, 'y'),
    ];
    assert_eq!(
        map.extend_sorted(clash),
        Err(IntervalError::Overlap {
            new: Range { first: 450, last: 460 },
            existing: Range { first: 400, last: 499 },
        })
    );
    assert_eq!(map, before, "a failed extend changes nothing");
    let clash_old = vec![(Range { first: 150, last: 160 }, 'z')];
    assert!(map.extend_sorted(clash_old).is_err());
    let bad = vec![(Range { first: 9, last: 1 }, 'z')];
    assert!(matches!(
        map.extend_sorted(bad),
        Err(IntervalError::InvalidRange(_))
    ));
    assert_eq!(map, before);
    assert!(
        IntervalError::InvalidRange(Range { first: 9, last: 1 })
            .to_string()
            .contains("0x9")
    );
}
