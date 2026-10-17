# ADR-0026: Std-only benchmark harness

Status: Accepted
Date: 2026-10-17
Verified by: AC-171, AC-202

## Context

- The owner asks for a std-only benchmark harness instead of criterion (ADR-0001).
- Wall-clock gates depend on the host and on its load. Revision 1 gave two thresholds for one gate.

## Decision

- `testkit::bench` runs each benchmark with `std::hint::black_box` and `std::time::Instant`: 3 warm-up runs, then 31 samples.
- It reports the median and the median absolute deviation (MAD).
- Gate: the median is at most the value in `perf/budget.json`. There is no second factor.
- When MAD / median is above 10%, the harness runs the benchmark again, up to 3 times. The last run counts.
- Benchmarks run in tier 2 only, in a release build. The report records the CPU model and the rustc version.
- `xtask bench` writes `perf/report.json`. Metrics: decode throughput, ELF load time, T2 analysis time, small-call overhead and cold start to the first `server/discover` response.

## Alternatives

- criterion. Rejected by ADR-0001.
- The mean of one run. Rejected: noisy under load.
- Benchmarks in tier 1. Rejected: debug builds and host load make them flaky.

## Consequences

- Budget changes are file changes that review sees.
- A slow host can fail the gate. The report names the CPU model, so review can tell host changes from regressions.
