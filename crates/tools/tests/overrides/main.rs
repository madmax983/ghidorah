//! The tier-1 tests of the override and type tools of WP-22b: `func_edit`, `type_get` and
//! `type_edit`.
//!
//! The tests run the tools through the dispatcher on a [`ghidorah_tools::Session`] with the
//! analysis engine. `support.rs` holds the registry of the tests: the shipped tools and the
//! three tools in the catalog order of design Section 10.3.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod func_edit;
mod reanalysis;
mod registry;
mod support;
mod types;
