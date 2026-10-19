//! The tier-1 tests of `func_similar` (WP-29): twins on the T2 fixtures (AC-238), determinism
//! (AC-239), the rename batch (AC-241), the argument caps, the hints and the PE32+ fixture
//! `pe_main.exe` (WP-30).
//!
//! The tests run the tool through the dispatcher on a [`ghidorah_tools::Session`].
//! `support.rs` holds the registry of the tests: the shipped registry with `func_similar` at
//! its catalog place. It also caches one analyzed program per fixture.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod calls;
mod pe;
mod registry;
mod rename;
mod support;
mod twins;
