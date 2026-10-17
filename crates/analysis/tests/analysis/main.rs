//! The tier-1 tests of `ghidorah-analysis` (WP-15).
//!
//! All tests run in this one test binary, so the coverage run sees one copy of each function.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod blobs;
mod callgraph;
mod cfg;
mod discovery;
mod errors;
mod noreturn;
mod publish;
mod raw;
mod sched;
mod support;
mod why;
