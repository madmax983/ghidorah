//! The std-only benchmark harness of ADR-0026.
//!
//! [`measure`] runs 3 warm-up runs and then 31 timed samples. It reports the
//! median and the median absolute deviation (MAD). When MAD / median is above
//! 10%, it measures again, up to 3 runs in total. The last run counts.
//! Benchmarks run in tier 2 only, in a release build.

use std::time::Instant;

/// The number of warm-up runs before the samples.
pub const WARMUP: usize = 3;

/// The number of timed samples in one run.
pub const SAMPLES: usize = 31;

/// The largest number of runs of one benchmark.
pub const MAX_RUNS: u32 = 3;

/// The largest stable spread (MAD / median) in permille.
pub const MAX_SPREAD_PERMILLE: u64 = 100;

/// The statistics of one benchmark run, in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// The median sample.
    pub median_ns: u64,
    /// The median absolute deviation of the samples.
    pub mad_ns: u64,
    /// The number of runs that [`measure`] used.
    pub runs: u32,
}

impl Stats {
    /// Computes the statistics of `samples`. An empty slice gives `None`.
    #[must_use]
    pub fn from_samples(samples: &[u64]) -> Option<Self> {
        let _ = samples;
        None
    }

    /// Returns MAD / median in permille. A zero median gives 0.
    #[must_use]
    pub const fn spread_permille(&self) -> u64 {
        0
    }

    /// Returns `true` when the spread is at most [`MAX_SPREAD_PERMILLE`].
    #[must_use]
    pub const fn stable(&self) -> bool {
        false
    }
}

/// Returns the median of `values`. For an even count it is the lower middle value.
///
/// The function sorts `values`. An empty slice gives 0.
#[must_use]
pub fn median(values: &mut [u64]) -> u64 {
    let _ = values;
    0
}

/// Measures `f` with the warm-up, sample and repeat rules of this module.
pub fn measure<R>(mut f: impl FnMut() -> R) -> Stats {
    let start = Instant::now();
    let _ = std::hint::black_box(f());
    let _ = start.elapsed();
    Stats {
        median_ns: 0,
        mad_ns: 0,
        runs: 0,
    }
}

/// The result of one benchmark against its budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The benchmark name.
    pub name: String,
    /// The measured statistics.
    pub stats: Stats,
    /// The budget for the median, in nanoseconds.
    pub budget_ns: u64,
    /// `true` when the median is at most the budget.
    pub ok: bool,
}

impl Verdict {
    /// Compares `stats` with `budget_ns`.
    #[must_use]
    pub fn new(name: &str, stats: Stats, budget_ns: u64) -> Self {
        Self {
            name: name.to_string(),
            stats,
            budget_ns,
            ok: false,
        }
    }

    /// Returns one JSON object with fixed key order and integer values only.
    #[must_use]
    pub fn to_json(&self) -> String {
        String::new()
    }
}

/// Returns the CPU model name from `/proc/cpuinfo`, or `unknown`.
#[must_use]
pub fn cpu_model() -> String {
    String::new()
}
