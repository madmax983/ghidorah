//! The tests of the `facts` module (WP-24): the relation catalog, the checker and why trees.
//!
//! The tests load fixtures, run the analysis to completion and check atoms directly.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod check;
mod explain;
mod relations;
mod support;
