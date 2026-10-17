//! The std-only benchmark harness of ADR-0026.
//!
//! [`measure`] runs 3 warm-up runs and then 31 timed samples. It reports the
//! median and the median absolute deviation (MAD). When MAD / median is above
//! 10%, it measures again, up to 3 runs in total. The last run counts.
//! Benchmarks run in tier 2 only, in a release build.

use std::fmt::Write as _;
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
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        let median_ns = median(&mut sorted);
        let mut deviations: Vec<u64> = samples.iter().map(|&s| s.abs_diff(median_ns)).collect();
        let mad_ns = median(&mut deviations);
        Some(Self {
            median_ns,
            mad_ns,
            runs: 1,
        })
    }

    /// Returns MAD / median in permille. A zero median gives 0.
    #[must_use]
    pub fn spread_permille(&self) -> u64 {
        if self.median_ns == 0 {
            return 0;
        }
        let permille = u128::from(self.mad_ns) * 1000 / u128::from(self.median_ns);
        u64::try_from(permille).unwrap_or(u64::MAX)
    }

    /// Returns `true` when the spread is at most [`MAX_SPREAD_PERMILLE`].
    #[must_use]
    pub fn stable(&self) -> bool {
        self.spread_permille() <= MAX_SPREAD_PERMILLE
    }
}

/// Returns the median of `values`. For an even count it is the lower middle value.
///
/// The function sorts `values`. An empty slice gives 0.
#[must_use]
pub fn median(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[(values.len() - 1) / 2]
}

/// Runs one measurement: the warm-up runs and the timed samples.
fn one_run<R>(f: &mut impl FnMut() -> R) -> Stats {
    for _ in 0..WARMUP {
        std::hint::black_box(f());
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        std::hint::black_box(f());
        let ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        samples.push(ns);
    }
    Stats::from_samples(&samples).unwrap_or(Stats {
        median_ns: 0,
        mad_ns: 0,
        runs: 1,
    })
}

/// Measures `f` with the warm-up, sample and repeat rules of this module.
pub fn measure<R>(mut f: impl FnMut() -> R) -> Stats {
    let mut run = 1;
    loop {
        let mut stats = one_run(&mut f);
        stats.runs = run;
        if stats.stable() || run >= MAX_RUNS {
            return stats;
        }
        run += 1;
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
            ok: stats.median_ns <= budget_ns,
        }
    }

    /// Returns one JSON object with fixed key order and integer values only.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut name = String::new();
        for c in self.name.chars() {
            match c {
                '"' => name.push_str("\\\""),
                '\\' => name.push_str("\\\\"),
                c if u32::from(c) < 0x20 => {
                    let _ = write!(name, "\\u{:04x}", u32::from(c));
                }
                c => name.push(c),
            }
        }
        format!(
            "{{\"name\":\"{}\",\"median_ns\":{},\"mad_ns\":{},\"runs\":{},\"budget_ns\":{},\"ok\":{}}}",
            name, self.stats.median_ns, self.stats.mad_ns, self.stats.runs, self.budget_ns, self.ok
        )
    }
}

/// Returns the CPU model name from `/proc/cpuinfo`, or `unknown`.
#[must_use]
pub fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
