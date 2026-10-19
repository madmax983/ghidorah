//! The tier-1 tests of the IR-based analyzers of `ghidorah-analysis` (WP-19), of the
//! code-pointer seeds (WP-19b) and of the gap components (WP-19c). The `pe` module tests the PE
//! seeds and parameters (WP-30).
//!
//! The derived views (function IR, stack frames, method A, parameters, syscall sites, call
//! arguments and the start call) run over the published facts of the analyzers. The pipeline
//! tests run the shipped analyzer list, with the WP-19 rows of the registry.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod blob;
mod callargs;
mod cc;
mod codeptr;
mod fir;
mod gapcomp;
mod jumptable;
mod main_discovery;
mod pe;
mod pipeline;
mod reanalysis;
mod stack;
mod support;
mod syscalls;
mod tailcall;
