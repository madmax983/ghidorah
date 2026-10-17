//! The tier-1 tests of `ghidorah-analysis` (WP-15, WP-17a).
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
mod gaps;
mod lang;
mod metrics;
mod noreturn;
mod publish;
mod raw;
mod refs;
mod sched;
mod strings;
mod support;
mod why;
