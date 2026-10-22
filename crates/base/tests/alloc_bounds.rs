//! Allocation bounds of the scaling paths of `ghidorah-base`.
//!
//! This binary installs the counting allocator of `ghidorah-oracle`. Each test counts the
//! bytes that one path allocates for an input of size `n` and of size `2 n`. The count of
//! a fixed input is the same on each run, so the tests use no clock. A linear path allocates
//! about twice the bytes for twice the input. A path that copies its state on each step
//! allocates about four times the bytes.

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]

use ghidorah_base::{IntervalMap, Range};
use ghidorah_oracle::alloc::CountingAlloc;

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

/// The bytes that `n` calls of `extend_sorted` in address order allocate.
fn appends(n: u64) -> u64 {
    let (_map, stats) = ALLOC.measure(|| {
        let mut map = IntervalMap::new();
        for i in 0..n {
            let r = Range::new(i * 16, i * 16 + 5).expect("a range");
            map.extend_sorted(vec![(r, i)]).expect("no overlap");
        }
        map
    });
    stats.allocated_bytes
}

/// Bodies in address order go on the end of the map. A copy of the map for each call made
/// the allocated bytes grow with the square of the calls.
#[test]
fn regress_extend_sorted_allocates_linearly() {
    let (small, large) = (appends(5_000), appends(10_000));
    assert!(
        large * 2 <= small * 5,
        "twice the calls allocate {large} bytes, not about 2 x {small}"
    );
}
