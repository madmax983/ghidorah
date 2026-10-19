//! The `xtask bench` command: the benchmarks of design Section 13.10 (ADR-0026).
//!
//! The command builds the release `ghidorah` binary and drives it as a child process. Each
//! benchmark uses the harness of `testkit::bench`: 3 warm-up runs, 31 samples, and up to 3
//! runs while the spread is above 10%. The gate is the median against `perf/budget.json`.
//!
//! | Key | Sample |
//! |---|---|
//! | `cold_start_ms` | start `ghidorah mcp` and read the `server/discover` reply (AC-171) |
//! | `call_overhead_us` | one `calc` call through a running `ghidorah jsonl` |
//! | `decode_us` | one `mem_read` sweep of 500 instructions of a T2 fixture |
//! | `load_ms` | `ghidorah call binary_load` of a T2 fixture with no analysis |
//! | `analysis_t2_ms` | `ghidorah call binary_load` of a T2 fixture with the full analysis |
//!
//! Output: `{ ok, cpu, <key>: { median, mad, runs, budget, ok } }` with values in the unit of
//! the key. AC-171 reads `/cold_start_ms/median`. AC-202 reads `/ok`.

use std::collections::BTreeMap;
use std::path::Path;

use ghidorah_testkit::bench::Stats;

use crate::Error;
use crate::json::Value;

/// The budget file, relative to the workspace root.
pub const BUDGET_PATH: &str = "perf/budget.json";

/// The T2 fixture of the load, decode and analysis benchmarks.
pub const T2_FIXTURE: &str = "fixtures/bin/large.gcc-O2";

/// The unit of a benchmark value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unit {
    /// Milliseconds.
    Ms,
    /// Microseconds.
    Us,
}

/// One benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bench {
    /// The key in the output and in `perf/budget.json`.
    pub key: &'static str,
    /// The unit of the values.
    pub unit: Unit,
}

/// The benchmarks in run order.
pub const BENCHES: &[Bench] = &[];

/// Reads the budgets of `perf/budget.json`: a JSON object of integer values.
///
/// # Errors
///
/// Returns [`Error::Data`] when the text is not such an object.
pub fn parse_budget(text: &str) -> Result<BTreeMap<String, u64>, Error> {
    let _ = text;
    Ok(BTreeMap::new())
}

/// Gives `ns` nanoseconds in `unit`, rounded up.
#[must_use]
pub const fn to_unit(ns: u64, unit: Unit) -> u64 {
    let _ = unit;
    ns
}

/// Gives the report of one benchmark: `{ median, mad, runs, budget, ok }`.
///
/// A benchmark with no budget is not `ok`.
#[must_use]
pub fn verdict(bench: &Bench, stats: &Stats, budget: Option<u64>) -> Value {
    let _ = (bench, stats, budget);
    Value::Null
}

/// Gives the JSON-RPC line of a `server/discover` request with `id`.
#[must_use]
pub fn discover_line(id: u64) -> String {
    let _ = id;
    String::new()
}

/// Runs `xtask bench [<key>..]`.
///
/// # Errors
///
/// Returns an error for an unknown key, a bad budget file, a build that fails or a child
/// process that does not answer.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let _ = (root, args);
    Err(Error::Usage("cargo xtask bench".to_owned()))
}
