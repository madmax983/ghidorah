//! Workspace gates and developer commands for ghidorah.
//!
//! The `xtask` binary dispatches to these modules. Each command prints one JSON object.
//! The tests in `xtask/tests/` call the same functions.
//!
//! Commands:
//!
//! | Command | Module | Purpose |
//! |---|---|---|
//! | `xtask gates` | [`gates`] | Runs the static workspace gates (AC-001 to AC-019, AC-223). |
//! | `xtask deps` | [`dag`] | Checks the crate edges and writes `docs/architecture/crates.mmd`. |
//! | `xtask ci` | [`ci`] | Runs the CI steps and records the time of each test. |
//! | `xtask cov` | [`cov`] | Measures line coverage with `llvm-tools` (ADR-0027). |
//! | `xtask ac` | [`ac`] | Checks the AC table of the design and runs its evidence. |
//! | `xtask ste` | [`ste`] | Checks the docs and comments with the STE checker of `testkit` (AC-025). |
//! | `xtask verify` | [`verify`] | Runs the Verus proofs of the kernel and writes `verify/results.json`. |

pub mod ac;
pub mod acrun;
pub mod ci;
pub mod cov;
pub mod dag;
pub mod error;
pub mod finding;
pub mod gates;
pub mod json;
pub mod manifest;
pub mod proc;
pub mod rustsrc;
pub mod scan;
pub mod ste;
pub mod verify;
pub mod workflow;
pub mod workspace;

pub use error::Error;
pub use finding::Finding;
