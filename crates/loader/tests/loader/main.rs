//! Tests of `ghidorah-loader` (WP-07): the probe, the ELF core loader, the raw loader and
//! the memory map.

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod builder;
mod golden;
mod malformed;
mod memmap;
mod probe;
mod raw;
mod readelf;
mod support;
