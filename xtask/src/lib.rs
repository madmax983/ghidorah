//! Workspace gates and developer commands for ghidorah.
//!
//! The `xtask` binary dispatches to these modules. Each command prints one JSON object.
//! The tests in `xtask/tests/` call the same functions.
//!
//! Commands:
//!
//! | Command | Module | Purpose |
//! |---|---|---|
//! | `xtask gates` | [`gates`] | Run the static workspace gates (AC-001 to AC-019, AC-223). |
//! | `xtask deps` | [`dag`] | Check the crate edges and write `docs/architecture/crates.mmd`. |
//! | `xtask ci` | [`ci`] | Run the CI steps and record the time of each test. |
//! | `xtask cov` | [`cov`] | Measure line coverage with `llvm-tools` (ADR-0027). |
//! | `xtask ac` | [`ac`] | Check the AC table of the design and run its evidence. |

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
pub mod workflow;
pub mod workspace;

pub use error::Error;
pub use finding::Finding;
