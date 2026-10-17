# ADR-0012: Deterministic output rules

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-186a, AC-186b, AC-187, AC-188, AC-189a to AC-189e, AC-223

## Context

- Golden tests, eval baselines, prompt caching and record-and-replay need byte-identical output.
- `HashMap` iteration order is random. Time budgets stop work at different points under load. f64 formatting differs across hosts, and `NaN` is invalid JSON.
- Measured on 1.97 with edition 2024: `std::env::set_var` is an unsafe function, and the workspace denies unsafe code. So a test cannot switch environment variables in process.
- std gives no way to choose a `RandomState` seed.
- Output that holds absolute paths differs between machines.

## Decision

- Output paths use `BTreeMap` or sorted `Vec`. `clippy.toml` disallows `HashMap`, `HashSet` and `RandomState` in production crates. An exception needs `#[expect(.., reason)]` on an internal lookup that never reaches output.
- Analysis is single-threaded. Work order is `(priority, analyzer name, address)`. Graph passes iterate in reverse post-order with an address tie-break.
- Every semantic stop uses fuel. `max_ms` is only a safety net. A time stop reports `stopped_by: "time"`, `deterministic: false` and `W_TIME_STOP`.
- The `cli` crate reads `GHIDORAH_FIXED_TIME` and `GHIDORAH_EVAL` once into `RunConfig { fixed_time, eval_mode }`. It passes `RunConfig` and a `Clock` as arguments. Tests build `RunConfig` directly or spawn the binary with `Command::env`. No crate calls `set_var` or `remove_var`.
- No output field holds wall-clock time, except crash files.
- No floats on output paths: confidence as `u8`, `est_tokens` as an integer.
- Seeds derive from content (body hashes) or fixed constants. IDs, cursors and `crash_id` hold no time and no random parts. `crash_id` is a prefix of `sha256(tool, JCS(args), rev)`.
- Output paths are relative to the project directory.
- `tools/list` has a fixed order. Progress notifications fire per fuel slice.

## Alternatives

- Time budgets for analysis. Rejected: results depend on load.
- `HashMap` with a fixed hasher. Rejected: one missed site breaks the rule. The type ban is simpler to check.
- Two processes with different `RandomState` seeds. Rejected: std cannot choose a seed. Three processes and the type ban cover it.

## Consequences

- Three-process byte equality is a gate (AC-186a, AC-186b), plus metamorphic relations with `relocate` (AC-189e).
- Parallel analysis needs a deterministic merge when it comes later.

## Amendment 2026-10-17

- `RunConfig`, the `set_var` ban, three processes, relative paths, `crash_id` and the `relocate` relation are new.
