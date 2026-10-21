//! The tier-1 tests of `ghidorah-base`.
//!
//! All tests except the fuzz target are in this one test binary. So the coverage run
//! sees one copy of each function. The crate has no unit-test binary.

mod addr_expr;
mod address;
mod bintext;
mod catalog;
mod dym;
mod glob;
mod hash;
mod id;
mod interval;
mod misc;
mod support;
