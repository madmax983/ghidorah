//! The tier-1 tests of `ghidorah-decomp` (WP-21).
//!
//! The structurer tests run on random shapes. The view tests run on random L1 programs and on
//! the functions of the fixtures.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod corpus;
mod fixtures;
mod fold;
mod goto;
mod oracle;
mod progs;
mod regress;
mod shapes;
mod structure;
mod units;
