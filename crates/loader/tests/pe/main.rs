//! Tests of the PE32+ loader of `ghidorah-loader` (WP-30, design Sections 4.9 to 4.15).
//!
//! The fixture tests compare the model of each PE fixture with the `llvm-readobj` goldens of
//! `tests/golden/loader/pe/` and the truth files of `fixtures/truth/pe/`. The variant tests
//! use the `PeBuilder` of `ghidorah-testkit`.

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]
#![allow(clippy::panic, reason = "a test fails through a panic")]

mod extras;
mod headers;
mod mapping;
mod readobj;
mod support;
mod tables;
