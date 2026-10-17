//! The tier-1 tests of `func_get include decomp` and of the IR level `l1` (WP-23).
//!
//! The registry of the tests holds `func_get` with the `decomp` section
//! ([`ghidorah_tools::handlers::func_get::SPEC_DECOMP`]). The edits of the tests go through
//! [`ghidorah_tools::Session::transact`], the write path of the edit tools.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod comments;
mod section;
mod support;
mod vars;
mod windows;
