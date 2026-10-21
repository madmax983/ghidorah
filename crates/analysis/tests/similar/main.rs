//! The tests of function similarity (WP-29, design Section 7.13): feature streams, vectors,
//! the vector cache, the Q16 arithmetic, scores, matches and the name proposal rules.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod features;
mod index;
mod proposals;
mod support;
mod vectors;
