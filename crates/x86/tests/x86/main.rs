//! The tests of `ghidorah-x86` (design Sections 5, 6.3, 15.7 and 15.8).

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test helpers stop on bad fixture data")]

mod boundary;
mod common;
mod coverage;
mod fixtures;
mod host;
mod json;
mod leaf;
mod lift;
mod model;
mod oracle;
mod oracle_random;
mod print;
mod props;
mod spec;
mod vectors;
