# Performance budgets

`cargo xtask bench` measures the release `ghidorah` binary (design Section 13.10, ADR-0026).
It runs in tier 2 only. Each benchmark has 3 warm-up runs and 31 samples. The harness runs again
when the spread is above 10%, up to 3 runs.

The gate compares the median of each benchmark with its key in `budget.json` (AC-171, AC-202).
The command prints one JSON object with the median, the spread, the number of runs and the
budget of each key. It also prints the CPU model of the host.

| Key | Unit | Sample |
|---|---|---|
| `cold_start_ms` | ms | The time from the start of `ghidorah mcp` to its reply to `server/discover`. |
| `call_overhead_us` | µs | The time of one `calc` call through a running `ghidorah jsonl`, with the reply. |
| `decode_us` | µs | Send one `mem_read` sweep of 500 instructions of `fixtures/bin/large.gcc-O2`. |
| `load_ms` | ms | Run `ghidorah call binary_load` on the T2 fixture with no analysis. |
| `analysis_t2_ms` | ms | Run `ghidorah call binary_load` on the T2 fixture with the full analysis. |
| `similar_2k_ms` | ms | The test `ac_243_similar_2k_budget` of WP-29 reads this key. |

A budget change needs a measurement on the 4-core build host. Put the measured median and the
CPU model in the commit message.
