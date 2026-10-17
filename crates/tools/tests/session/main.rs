//! The tier-1 tests of the session, the resolver and the helper tools of WP-13b.
//!
//! The tests run the tools through the dispatcher on a [`ghidorah_tools::Session`].
//! `support.rs` holds the registry of the tests and the session helpers.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]

mod calc;
mod coerce;
mod cursor;
mod examples;
mod load;
mod profiles;
mod resolve;
mod search;
mod session;
mod support;
