//! The tests of `ghidorah-x86` (design Sections 5 and 15.7).

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test helpers stop on bad fixture data")]

mod boundary;
mod common;
mod fixtures;
mod model;
mod oracle;
mod print;
mod props;
mod spec;
