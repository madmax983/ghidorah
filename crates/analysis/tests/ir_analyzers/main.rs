//! The tier-1 tests of the IR-based analyzers of `ghidorah-analysis` (WP-19).
//!
//! The derived views (function IR, stack frames, method A, parameters, syscall sites, call
//! arguments and the start call) run over the published facts of the WP-15 analyzers. The
//! pipeline tests need the WP-19 analyzer rows of the registry, so they carry an ignore
//! reason until the register step.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod blob;
mod callargs;
mod cc;
mod fir;
mod jumptable;
mod main_discovery;
mod pipeline;
mod stack;
mod support;
mod syscalls;
mod tailcall;
