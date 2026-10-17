//! The tier-1 tests of the memory tools of WP-22a: `symbol_rename`, `comment_set`,
//! `note_write` and `session_brief`.
//!
//! The tests run the tools through the dispatcher on a [`ghidorah_tools::Session`].
//! `support.rs` holds the registry of the tests: the shipped tools and the memory tools in the
//! catalog order of design Section 10.3. It also caches one analyzed program per fixture.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod brief;
mod comments;
mod cursors;
mod notes;
mod registry;
mod rename;
mod sets;
mod support;
