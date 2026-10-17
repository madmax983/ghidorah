//! Dev-only test oracles of ghidorah (design Section 2.1, ADR-0025).
//!
//! This crate never enters the closure of the `ghidorah` binary. It is the only crate that
//! holds `unsafe` code. Only `xtask` and dev tests use it.
//!
//! - [`alloc::CountingAlloc`]: a global allocator that counts the heap bytes of each thread,
//!   for the bounded-allocation gate of the loader (AC-055).
#![expect(
    unsafe_code,
    reason = "a global allocator needs `unsafe impl GlobalAlloc` (ADR-0025)"
)]

pub mod alloc;
