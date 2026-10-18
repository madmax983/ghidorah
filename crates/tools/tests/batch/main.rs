//! The tier-1 tests of `batch_run` (WP-25) and of the registry-wide rules over the full
//! registry.
//!
//! `support.rs` holds the registry of the tests: the shipped tools and `batch_run`.
//! The tests run the tools through the dispatcher on a [`ghidorah_tools::Session`].

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(
    clippy::unnecessary_wraps,
    reason = "test handlers have the handler type, which returns a Result"
)]

mod budgets;
mod guards;
mod readback;
mod refs;
mod registry;
mod run;
mod support;
mod triggers;
mod validate;
