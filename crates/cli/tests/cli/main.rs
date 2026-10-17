//! The tier-1 tests of the `ghidorah` command line and MCP server.
//!
//! Most tests run in this one test binary, so the coverage run sees one copy of each
//! function. The e2e transcript and the fuzz target have their own binaries.

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(
    clippy::unnecessary_wraps,
    reason = "test handlers have the handler type, which returns a Result"
)]

#[path = "../common/mod.rs"]
mod common;

mod analysis_run;
mod argv;
mod cancel;
mod config;
mod doctor;
mod era;
mod exit_codes;
mod jsonl;
mod line_cap;
mod purity;
mod record;
mod select;
mod surface;
mod tool_errors;
