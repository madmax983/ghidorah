//! The tier-1 tests of `ghidorah-ir`.
//!
//! All tests are in this one test binary, so the coverage run sees one copy of each function.

mod arena;
mod checker;
mod common;
mod fusion;
mod graph;
mod interp;
mod l1;
mod local;
mod ops;
mod passes;
mod print;
mod random;
mod sem;
mod size;
mod ssa;
mod ssagen;
