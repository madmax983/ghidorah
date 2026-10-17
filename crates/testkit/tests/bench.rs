//! Tests of the benchmark harness (ADR-0026).

use std::cell::Cell;

use ghidorah_testkit::bench::{self, MAX_RUNS, SAMPLES, Stats, Verdict, WARMUP};

#[test]
fn stats_median_and_mad_of_fixed_samples() {
    let stats = Stats::from_samples(&[5, 1, 3, 2, 4]);
    assert_eq!(
        stats,
        Some(Stats {
            median_ns: 3,
            mad_ns: 1,
            runs: 1
        })
    );
    assert_eq!(Stats::from_samples(&[]), None);
}

#[test]
fn median_of_even_count_is_lower_middle() {
    let mut v = [40, 10, 30, 20];
    assert_eq!(bench::median(&mut v), 20);
    assert_eq!(bench::median(&mut []), 0);
}

#[test]
fn spread_and_stable_rule() {
    let wide = Stats {
        median_ns: 1000,
        mad_ns: 101,
        runs: 1,
    };
    let narrow = Stats {
        median_ns: 1000,
        mad_ns: 100,
        runs: 1,
    };
    assert_eq!(wide.spread_permille(), 101);
    assert!(!wide.stable());
    assert!(narrow.stable());
    let zero = Stats {
        median_ns: 0,
        mad_ns: 0,
        runs: 1,
    };
    assert_eq!(zero.spread_permille(), 0);
    assert!(zero.stable());
}

#[test]
fn measure_uses_warmups_and_samples() {
    let calls = Cell::new(0usize);
    let stats = bench::measure(|| {
        calls.set(calls.get() + 1);
        std::hint::black_box(calls.get())
    });
    assert!((1..=MAX_RUNS).contains(&stats.runs), "{stats:?}");
    let per_run = WARMUP + SAMPLES;
    let runs = usize::try_from(stats.runs).unwrap_or(usize::MAX);
    assert_eq!(calls.get(), per_run * runs);
}

#[test]
fn verdict_compares_median_with_budget() {
    let stats = Stats {
        median_ns: 500,
        mad_ns: 7,
        runs: 2,
    };
    let ok = Verdict::new("decode", stats, 500);
    assert!(ok.ok);
    let slow = Verdict::new("decode", stats, 499);
    assert!(!slow.ok);
    assert_eq!(
        ok.to_json(),
        "{\"name\":\"decode\",\"median_ns\":500,\"mad_ns\":7,\"runs\":2,\"budget_ns\":500,\"ok\":true}"
    );
}

#[test]
fn cpu_model_is_not_empty() {
    assert!(!bench::cpu_model().is_empty());
}
