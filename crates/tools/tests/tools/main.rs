//! The tier-1 tests of `ghidorah-tools`.
//!
//! All tests are in this one test binary, so the coverage run sees one copy of each function.
//! The test registry of WP-13a lives in `tests/support/test_registry.rs`.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]

#[path = "../support/test_registry.rs"]
mod test_registry;

mod args;
mod budget;
mod common;
mod content;
mod errors;
mod examples;
mod hints;
mod lint;
mod outshape;
mod pipeline;
mod schema;
mod ste;
