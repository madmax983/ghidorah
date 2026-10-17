//! K2 tier-1 tests: the boundary table and random inputs against a `u128` model (AC-029).

use ghidorah_kernel::{Mapping, Range, range_last, va_to_file};
use ghidorah_testkit::pbt::{Gen, check};

const MAX: u64 = u64::MAX;

/// The `u128` model of `range_last`.
fn model_last(start: u64, len: u64) -> Option<u64> {
    if len == 0 {
        return None;
    }
    u64::try_from(u128::from(start) + u128::from(len) - 1).ok()
}

/// The `u128` model of `va_to_file`.
fn model_va_to_file(map: &Mapping, va: u64) -> Option<u64> {
    let (va, start) = (u128::from(va), u128::from(map.va));
    if va < start || va >= start + u128::from(map.file_size) {
        return None;
    }
    u64::try_from(u128::from(map.file_off) + (va - start)).ok()
}

#[test]
fn ac_029_range_boundary_table() {
    let last_rows: &[(u64, u64, Option<u64>)] = &[
        (MAX, 1, Some(MAX)),
        (MAX, 2, None),
        (MAX, 0, None),
        (0, 0, None),
        (1, MAX, None),
        (0, MAX, Some(MAX - 1)),
        (0, 1, Some(0)),
        (5, 0, None),
        (0x1000, 0x10, Some(0x100f)),
        (MAX - 9, 10, Some(MAX)),
        (MAX - 9, 11, None),
    ];
    for &(start, len, want) in last_rows {
        assert_eq!(
            range_last(start, len),
            want,
            "range_last({start:#x}, {len:#x})"
        );
        let r = Range::with_len(start, len);
        assert_eq!(r.map(|r| (r.first, r.last)), want.map(|l| (start, l)));
    }

    assert_eq!(Range::new(2, 1), None);
    assert_eq!(Range::new(1, 1), Some(Range { first: 1, last: 1 }));
    assert_eq!(
        Range::single(MAX),
        Range {
            first: MAX,
            last: MAX
        }
    );
    let full = Range {
        first: 0,
        last: MAX,
    };
    assert_eq!(full.len(), 1u128 << 64);
    assert!(!full.is_empty());
    assert!(full.contains(0) && full.contains(MAX));
    assert_eq!(full.offset_in(MAX), Some(MAX));
    let empty = Range { first: 2, last: 1 };
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
    assert!(!empty.contains(1) && !empty.contains(2));
    assert!(!empty.overlaps(&full) && !full.overlaps(&empty));
    assert_eq!(empty.offset_in(2), None);

    let a = Range {
        first: 10,
        last: 20,
    };
    let touch = Range {
        first: 21,
        last: 30,
    };
    let share = Range {
        first: 20,
        last: 30,
    };
    assert!(!a.overlaps(&touch) && !touch.overlaps(&a));
    assert!(a.overlaps(&share) && share.overlaps(&a));
    assert!(a.overlaps(&a));
    assert_eq!(a.offset_in(9), None);
    assert_eq!(a.offset_in(10), Some(0));
    assert_eq!(a.offset_in(20), Some(10));
    assert_eq!(a.offset_in(21), None);
    assert_eq!(a.len(), 11);

    // A mapping of 0x100 file bytes at 0x1000. The memory after 0x10ff is the zero-fill tail.
    let map = Mapping {
        va: 0x1000,
        file_off: 0x200,
        file_size: 0x100,
    };
    let va_rows: &[(u64, Option<u64>)] = &[
        (0xfff, None),
        (0x1000, Some(0x200)),
        (0x10ff, Some(0x2ff)),
        (0x1100, None),
        (0x1fff, None),
        (MAX, None),
    ];
    for &(va, want) in va_rows {
        assert_eq!(va_to_file(&map, va), want, "va_to_file({va:#x})");
    }
    let empty_map = Mapping {
        va: 0x1000,
        file_off: 0,
        file_size: 0,
    };
    assert_eq!(va_to_file(&empty_map, 0x1000), None);
    let top = Mapping {
        va: MAX - 1,
        file_off: MAX - 1,
        file_size: 10,
    };
    assert_eq!(va_to_file(&top, MAX - 1), Some(MAX - 1));
    assert_eq!(va_to_file(&top, MAX), Some(MAX));
    let wrap = Mapping {
        va: MAX - 1,
        file_off: MAX,
        file_size: 2,
    };
    assert_eq!(va_to_file(&wrap, MAX - 1), Some(MAX));
    assert_eq!(
        va_to_file(&wrap, MAX),
        None,
        "the file offset goes past u64::MAX"
    );
}

fn gen_range(g: &mut Gen) -> Range {
    Range {
        first: g.u64(),
        last: g.u64(),
    }
}

#[test]
fn k2_range_random_against_u128() {
    check("k2_range_random_against_u128", 5_000, |g: &mut Gen| {
        let (start, len, x) = (g.u64(), g.u64(), g.u64());
        if range_last(start, len) != model_last(start, len) {
            return Err(format!("range_last({start:#x}, {len:#x})"));
        }
        let r = gen_range(g);
        let o = gen_range(g);
        let valid = r.first <= r.last;
        let has = valid && r.first <= x && x <= r.last;
        let len_model = if valid {
            u128::from(r.last) - u128::from(r.first) + 1
        } else {
            0
        };
        let overlap = valid && o.first <= o.last && r.first.max(o.first) <= r.last.min(o.last);
        let got = (
            r.len(),
            r.is_empty(),
            r.contains(x),
            r.overlaps(&o),
            r.offset_in(x),
        );
        let want = (len_model, !valid, has, overlap, has.then(|| x - r.first));
        if got != want {
            return Err(format!("{r:?} {o:?} x={x:#x}: {got:?} != {want:?}"));
        }
        if Range::new(r.first, r.last) != valid.then_some(r) {
            return Err(format!("Range::new for {r:?}"));
        }
        let map = Mapping {
            va: g.u64(),
            file_off: g.u64(),
            file_size: g.u64(),
        };
        let va = if g.bool() {
            map.va.wrapping_add(g.u64() % 512)
        } else {
            g.u64()
        };
        if va_to_file(&map, va) != model_va_to_file(&map, va) {
            return Err(format!("va_to_file({map:?}, {va:#x})"));
        }
        Ok(())
    });
}
