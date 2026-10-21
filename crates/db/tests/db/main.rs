//! Tests of the public read API of `ghidorah-db` (WP-11a).

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod fixtures;
mod hostile;
mod provenance;
