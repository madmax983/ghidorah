//! Std-only test kit for the ghidorah workspace.
//!
//! The kit is a dev crate. It never enters the `ghidorah` binary.
//! It has no dependencies, so every crate can use it in tests.
//!
//! Modules:
//!
//! - [`rng`]: `SplitMix64`, `Xoshiro256ss` and the Lemire `below` method.
//! - [`pbt`]: property tests over choice sequences, with shrink.
//! - [`fuzz`]: havoc mutation, a case runner with pending files, stage counters and a panic counter.
//! - [`golden`]: golden files with a header line and `GHIDORAH_BLESS`.
//! - [`model`]: model-based tests over random operation sequences.
//! - [`mod@bench`]: the benchmark harness of ADR-0026.
//! - [`fixture`]: one built fixture per key in each test binary.
//! - [`ste`]: the ASD-STE100 checker with rules STE-1 to STE-8 of ADR-0019.
//! - [`elf`]: `ElfBuilder`, a writer for small ELF test files.
//! - [`pe`]: `PeBuilder`, a writer for small PE32+ test files (WP-30).

pub mod bench;
pub mod elf;
pub mod fixture;
pub mod fuzz;
pub mod golden;
pub mod model;
pub mod pbt;
pub mod pe;
pub mod rng;
pub mod ste;
