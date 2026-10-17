# ADR-0001: Zero third-party dependencies

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-001a, AC-001b, AC-001c, AC-001d, AC-001e, AC-002, AC-005, AC-008

## Context

- The owner sets a hard constraint: the build uses the Rust standard library only.
- The constraint covers JSON, CLI parsing, MCP and JSON-RPC, hashing, PRNG, test harnesses and benchmarks.
- A dependency on `vstd` pulls in `proc-macro2`, `quote` and `syn` through `verus_builtin_macros` (research 3.10). An optional or dev dependency also breaks the rule.
- ghidorah reads hostile binaries. A small, audited trusted base is a security benefit.
- A check of `Cargo.lock` source keys alone misses a vendored path crate, `[patch]`, `[replace]` and a `[source]` replacement.

## Decision

- `cargo metadata --offline --locked` lists only the packages of design Section 2.1, each at `crates/<dir>/Cargo.toml` or `xtask/Cargo.toml`.
- Every dependency of every package is a workspace package or the built-in `proc_macro` crate.
- No `Cargo.toml` has `[patch]` or `[replace]`. `.cargo/config.toml` has no `[source]` or `[patch]` table.
- Every package sets `publish = false` and `license = "Apache-2.0"`. No `[[package]]` in `Cargo.lock` has a `source` key.
- First-party crates replace common libraries: `ghidorah-json` (JSON, JCS, pointer), `ghidorah-base` (SHA-256, FNV-1a, hex, glob, did-you-mean), `ghidorah-testkit` (PRNG, property tests, shrink, fuzz, golden files, bench, STE checker), `ghidorah` (CLI parsing, MCP).
- `.cargo/config.toml` sets `[net] offline = true`, so a new registry dependency cannot resolve.
- First-party proc-macro crates use only the built-in `proc_macro` crate (`ghidorah-spec`).
- No `build.rs` uses the network or spawns processes.

## Alternatives

- A small allowlist of audited crates (`serde_json`, `thiserror`). Rejected: the owner rule allows no third-party crate.
- Vendored third-party crates as path dependencies. Rejected: they are third-party code. AC-001a catches them by path.
- An optional or dev dependency on `vstd`. Rejected: it pulls third-party proc-macro crates.

## Consequences

- The first-party primitives count against the line budget.
- Each primitive needs known-answer tests: JSONTestSuite, NIST SHA-256 vectors, SplitMix64 and xoshiro256** vectors.
- Supply-chain review is a set of gate tests in `xtask/tests/gates.rs`.
- No serde: persisted and output types use the `json_record!` macro for codecs (ADR-0002, ADR-0004).
- Verus stays outside Cargo (ADR-0011).

## Amendment 2026-10-17

- AC-001 was a source-key check only. It is now five sub-ACs (AC-001a to AC-001e) that also catch path crates, patch tables and source replacement.
