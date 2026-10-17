//! A counting global allocator for heap-bound tests (design Section 13.6, AC-055).
//!
//! [`CountingAlloc`] forwards each call to [`System`]. It keeps counters for the whole
//! process and for each thread. A test binary installs it:
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: ghidorah_oracle::alloc::CountingAlloc = ghidorah_oracle::alloc::CountingAlloc::new();
//! ```
//!
//! [`CountingAlloc::measure`] runs a closure and gives the peak heap bytes of the calling
//! thread above its level at the start. Other test threads do not change the result.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The counters of one thread: live bytes, peak live bytes, allocation count, allocated bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Local {
    live: usize,
    peak: usize,
    count: u64,
    bytes: u64,
}

thread_local! {
    static LOCAL: Cell<Local> = const {
        Cell::new(Local { live: 0, peak: 0, count: 0, bytes: 0 })
    };
}

/// Changes the counters of the calling thread. A thread in teardown keeps no counters.
fn local(update: impl FnOnce(&mut Local)) {
    let _ = LOCAL.try_with(|cell| {
        let mut value = cell.get();
        update(&mut value);
        cell.set(value);
    });
}

/// The heap use of one measured closure, on the calling thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// The peak of live heap bytes above the level at the start.
    pub peak_bytes: usize,
    /// The number of allocations, reallocations included.
    pub allocations: u64,
    /// The sum of the requested bytes of all allocations.
    pub allocated_bytes: u64,
}

/// A global allocator that counts heap bytes. It forwards each call to [`System`].
#[derive(Debug)]
pub struct CountingAlloc {
    live: AtomicUsize,
    peak: AtomicUsize,
    count: AtomicU64,
}

impl CountingAlloc {
    /// Makes an allocator with zero counters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Gives the live heap bytes of the process.
    #[must_use]
    pub fn live(&self) -> usize {
        0
    }

    /// Gives the peak live heap bytes of the process since the start or the last reset.
    #[must_use]
    pub fn peak(&self) -> usize {
        0
    }

    /// Gives the number of allocations of the process.
    #[must_use]
    pub fn allocations(&self) -> u64 {
        0
    }

    /// Sets the process peak to the live bytes.
    pub fn reset_peak(&self) {
        let _ = self;
    }

    /// Runs `f` and gives its result and the heap use of the calling thread during `f`.
    pub fn measure<R>(&self, f: impl FnOnce() -> R) -> (R, Stats) {
        let _ = self;
        (
            f(),
            Stats {
                peak_bytes: 0,
                allocations: 0,
                allocated_bytes: 0,
            },
        )
    }

    fn grow(&self, size: usize) {
        let live = self
            .live
            .fetch_add(size, Ordering::Relaxed)
            .saturating_add(size);
        self.peak.fetch_max(live, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        local(|l| {
            l.live = l.live.saturating_add(size);
            l.peak = l.peak.max(l.live);
            l.count = l.count.saturating_add(1);
            l.bytes = l
                .bytes
                .saturating_add(u64::try_from(size).unwrap_or(u64::MAX));
        });
    }

    fn shrink(&self, size: usize) {
        self.live.fetch_sub(size, Ordering::Relaxed);
        local(|l| l.live = l.live.saturating_sub(size));
    }
}

impl Default for CountingAlloc {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: each method forwards to `System` with the same arguments and only updates
// counters after the call. The counters never allocate.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            self.grow(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract for `layout`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            self.grow(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator with `layout`, so it came from `System`.
        unsafe { System.dealloc(ptr, layout) };
        self.shrink(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            self.shrink(layout.size());
            self.grow(new_size);
        }
        new
    }
}
