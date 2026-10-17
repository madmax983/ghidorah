# ADR-0027: Coverage measurement

Status: Accepted
Date: 2026-10-17
Verified by: AC-013

## Context

- The owner target is 85-90% line coverage.
- The research measured coverage with rustup `llvm-tools` only (research 3.10). It also proposed an 80% region gate.
- On stable 1.97, `#[coverage(off)]` is unstable, and branch and doctest coverage are nightly-only.
- A CLI binary that a test runs as a subprocess writes its own profile.

## Decision

- `xtask cov` sets `RUSTFLAGS="-C instrument-coverage"` and `LLVM_PROFILE_FILE=<abs target dir>/cov/%p-%m.profraw` in a separate `CARGO_TARGET_DIR`. It uses the same `RUSTFLAGS` for the test run and for the object listing.
- Objects: every test binary from `cargo test --no-run --message-format=json`, plus the `ghidorah` binary for CLI subprocess tests.
- Merge: `llvm-profdata merge -sparse`. Report: `llvm-cov export --summary-only` with the object list.
- Exclusions: `tests.rs` files, `crates/*/tests/` and the dev crates (`testkit`, `oracle`, `eval`, `xtask`).
- Gate (AC-013): line coverage per crate from `docs/budget.json`: 85% for the workspace, 90% for `json`, `loader`, `x86`, `ir`, `db`, `analysis` and `tools`, and 95% for `kernel`. The gate applies from the first WP that adds code to a crate.
- `xtask cov` reports region coverage but does not gate it.

## Alternatives

- grcov or tarpaulin. Rejected by ADR-0001.
- Nightly branch coverage. Rejected: `rust-toolchain.toml` pins stable 1.97.
- An 80% region gate (research 3.10). Rejected: without `#[coverage(off)]`, region numbers include code that tests cannot reach without a cfg change. The line gate plus property tests carry the evidence.

## Consequences

- One command gives per-crate JSON totals that `xtask ac` reads.
- CLI subprocess tests count toward coverage.
