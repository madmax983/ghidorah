//! Workspace gates and developer commands for ghidorah.
//!
//! The `xtask` binary dispatches to these modules. Each command prints one JSON object.
//! The tests in `xtask/tests/` call the same functions.
//!
//! Commands:
//!
//! | Command | Module | Purpose |
//! |---|---|---|
//! | `xtask gates` | [`gates`] | Runs the static workspace gates (AC-001 to AC-027, AC-223). |
//! | `xtask deps` | [`dag`] | Checks the crate edges and writes `docs/architecture/crates.mmd`. |
//! | `xtask ci` | [`ci`] | Runs the CI steps and records the time of each test. |
//! | `xtask cov` | [`cov`] | Measures line coverage with `llvm-tools` (ADR-0027). |
//! | `xtask ac` | [`ac`] | Checks the AC table of the design and runs its evidence. |
//! | `xtask ste` | [`ste`] | Checks the docs and comments with the STE checker of `testkit` (AC-025). |
//! | `xtask verify` | [`verify`] | Runs the Verus proofs of the kernel and writes `verify/results.json`. |
//! | `xtask fixtures` | [`fixtures`] | Builds the fixture corpus, its truth and its goldens, and checks them (WP-06). |
//! | `xtask fixtures build-pe` | [`fixtures_pe`] | Builds the PE32+ fixtures, their truth and their goldens (WP-30). |
//! | `xtask golden` | [`golden`] | Blesses goldens and checks their headers. |
//! | `xtask oracle` | [`oracle`] | Writes the native semantic vectors and the host boundary record (WP-16). |
//! | `xtask eval` | [`eval`] | Runs the eval harness, blesses its baselines and replays call records (WP-26). |
//! | `xtask fuzz` | [`fuzz`] | Runs long fuzz batches of every target in child processes (WP-27). |
//! | `xtask bench` | [`bench`](mod@bench) | Runs the release benchmarks against `perf/budget.json` (WP-27). |

pub mod ac;
pub mod acrun;
pub mod bench;
pub mod ci;
pub mod cov;
pub mod dag;
pub mod error;
pub mod eval;
pub mod finding;
pub mod fixtures;
pub mod fixtures_pe;
pub mod fuzz;
pub mod gates;
pub mod golden;
pub mod json;
pub mod manifest;
pub mod oracle;
pub mod proc;
pub mod rustsrc;
pub mod scan;
pub mod ste;
pub mod verify;
pub mod workflow;
pub mod workspace;

pub use error::Error;
pub use finding::Finding;
