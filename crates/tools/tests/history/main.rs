//! The tier-1 tests of the persistence and history tools of WP-20.
//!
//! The tests run `history_list`, `history_undo` and test tools through the dispatcher on a
//! [`ghidorah_tools::Session`]. `support.rs` holds the registry of the tests: the shipped
//! tools, the two history tools and the test tools.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(
    clippy::unnecessary_wraps,
    reason = "test handlers have the handler type, which returns a Result"
)]

mod list;
mod panic;
mod projects;
mod registry;
mod shadow;
mod support;
mod undo;
