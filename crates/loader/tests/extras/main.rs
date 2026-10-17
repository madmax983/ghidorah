//! Tests of the loader extras (WP-09): `.eh_frame`, import slots, PLT stubs and protections.

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod checksec;
mod ehframe;
mod encoding;
mod frames;
mod json;
mod plt;
mod support;
