//! The tier-1 tests of the session, the resolver and the helper tools of WP-13b.
//!
//! The tests run the tools through the dispatcher on a [`ghidorah_tools::Session`].
//! `support.rs` holds the registry of the tests and the session helpers.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(
    clippy::unnecessary_wraps,
    reason = "test handlers have the handler type, which returns a Result"
)]

mod analysis_run;
mod calc;
mod coerce;
mod cursor;
mod envelope;
mod examples;
mod load;
mod profiles;
mod registered;
mod resolve;
mod search;
mod session;
mod support;
