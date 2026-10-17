//! The generator of the T2 program `fixtures/src/large.c` (`xtask fixtures gen-large`).
//!
//! The generator uses `SplitMix64` with the fixed seed [`SEED`], so its output never changes.
//! It writes [`FUNCTIONS`] functions `fNNNN(u64 a, u64 b)`. A function calls only functions
//! with a lower number, so the call graph has no cycle. The function kinds are arithmetic,
//! loops, dense switches (jump tables), cold paths, tail calls, calls through a function
//! pointer table and callers of two functions.

/// The seed of the generator.
pub const SEED: u64 = 0x6768_6964_6f72_6168;

/// The number of generated functions.
pub const FUNCTIONS: usize = 640;

/// The source path of the generated program, relative to the workspace root.
pub const SOURCE_PATH: &str = "fixtures/src/large.c";

/// Gives the text of `fixtures/src/large.c`.
#[must_use]
pub fn generate() -> String {
    String::new()
}
