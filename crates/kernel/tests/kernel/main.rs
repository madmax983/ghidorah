//! The tier-1 tests of `ghidorah-kernel`, the second evidence of each proof (design Section 13.1).
//!
//! All kernel tests are in this one test binary. So the coverage run sees one copy of each
//! kernel function. The crate has no unit-test binary (`test = false` in `Cargo.toml`).

mod ac_006b_loop_invariant_builds;
mod budget;
mod proofs;
mod range;
mod rangeset;
mod reader;
mod source;
mod support;
