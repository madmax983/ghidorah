//! Dev-only test oracles of ghidorah (design Section 2.1, ADR-0025).
//!
//! This crate never enters the closure of the `ghidorah` binary. It is the only crate that
//! holds `unsafe` code. Only `xtask` and dev tests use it.
//!
//! - [`alloc::CountingAlloc`]: a global allocator that counts the heap bytes of each thread,
//!   for the bounded-allocation gate of the loader (AC-055).
//! - [`native`]: the native semantic oracle of the x86 lifter. It runs instruction forms on
//!   the host CPU, only from `xtask oracle semantics` (design Section 13.8).
#![expect(
    unsafe_code,
    reason = "a global allocator and the native oracle need unsafe code (ADR-0025)"
)]

pub mod alloc;
#[cfg(target_arch = "x86_64")]
pub mod native;
