//! The tier-1 tests of `ghidorah-tools`.
//!
//! All tests are in this one test binary, so the coverage run sees one copy of each function.
//! The test registry of WP-13a lives in `tests/support/test_registry.rs`.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "test tools panic on purpose")]
#![allow(
    clippy::unnecessary_wraps,
    reason = "test handlers have the handler type, which returns a Result"
)]

#[path = "../support/test_registry.rs"]
mod test_registry;

// The shipped registry, the sessions and the code triggers of the batch tests: `errors.rs`
// runs the trigger lines on the shipped registry (AC-142).
#[allow(dead_code, reason = "the tools tests use a part of the batch helpers")]
#[path = "../batch/support.rs"]
mod support;
#[path = "../support/triggers.rs"]
mod trigger_lines;

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
