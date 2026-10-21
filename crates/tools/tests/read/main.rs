//! The tier-1 tests of the read tools of WP-17b.
//!
//! The tests run the read tools through the dispatcher on a [`ghidorah_tools::Session`].
//! `support.rs` holds the registry of the tests: the shipped tools and the read tools in the
//! catalog order of design Section 10.3. It also caches one analyzed program per fixture.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod addr_info;
mod budget;
mod func_get;
mod func_list;
mod mem_read;
mod pe;
mod registry;
mod search;
mod support;
mod surface;
mod survey;
mod xref_list;
