//! The tier-1 tests of `fact_check` (WP-24): the verdict table, soundness, indirect target
//! overrides, why trees and the registry checks of the tool.
//!
//! The tests run the tools through the dispatcher on a [`ghidorah_tools::Session`] with the
//! analysis engine. `support.rs` holds the registry of the tests: the shipped tools and
//! `fact_check` in the catalog order of design Section 10.3.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod explain;
mod overrides;
mod registry;
mod soundness;
mod support;
mod verdicts;
