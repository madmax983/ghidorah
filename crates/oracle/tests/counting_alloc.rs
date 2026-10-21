//! Tests of the counting allocator. This binary installs it as the global allocator.

use std::hint::black_box;

use ghidorah_oracle::alloc::CountingAlloc;

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

#[test]
fn counting_alloc_counts() {
    // One live 1 MiB buffer gives a peak of at least 1 MiB on this thread.
    let ((), stats) = ALLOC.measure(|| {
        let buf = black_box(vec![7u8; 1 << 20]);
        assert_eq!(buf.len(), 1 << 20);
    });
    assert!(
        stats.peak_bytes >= 1 << 20,
        "peak {} below 1 MiB",
        stats.peak_bytes
    );
    assert!(
        stats.peak_bytes < 2 << 20,
        "peak {} far above 1 MiB",
        stats.peak_bytes
    );
    assert!(stats.allocations >= 1);
    assert!(stats.allocated_bytes >= 1 << 20);

    // Two buffers of 256 KiB, one after the other, peak at about 256 KiB, not 512 KiB.
    let ((), seq) = ALLOC.measure(|| {
        drop(black_box(vec![1u8; 256 << 10]));
        drop(black_box(vec![2u8; 256 << 10]));
    });
    assert!(seq.peak_bytes >= 256 << 10);
    assert!(
        seq.peak_bytes < 512 << 10,
        "peak {} counts freed memory",
        seq.peak_bytes
    );
    assert!(seq.allocated_bytes >= 512 << 10);

    // A growing vector counts each reallocation.
    let ((), grow) = ALLOC.measure(|| {
        let mut v: Vec<u64> = Vec::new();
        for i in 0..10_000u64 {
            v.push(black_box(i));
        }
        black_box(&v);
    });
    assert!(
        grow.allocations >= 10,
        "only {} allocations",
        grow.allocations
    );
    assert!(grow.peak_bytes >= 80_000);

    // A closure that allocates nothing gives zero.
    let (sum, none) = ALLOC.measure(|| black_box(2u64) + 3);
    assert_eq!(sum, 5);
    assert_eq!(none.allocations, 0);
    assert_eq!(none.peak_bytes, 0);

    // The process counters see the same heap.
    let before = ALLOC.allocations();
    let keep = black_box(vec![0u8; 4096]);
    assert!(ALLOC.allocations() > before);
    assert!(ALLOC.live() >= 4096);
    ALLOC.reset_peak();
    assert!(ALLOC.peak() >= 4096);
    drop(keep);
}
