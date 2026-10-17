# ADR-0011: Verus hybrid pattern in a verified leaf crate with a std-only stub proc-macro

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-005, AC-006a, AC-006b, AC-028 to AC-034, AC-035a to AC-035c

## Context

- Verus is not a crate. `vstd` pulls third-party crates (ADR-0001). Verus pins toolchain 1.98.1, and the project uses 1.97.0.
- Measured: the hybrid pattern builds with plain `cargo test` and verifies under Verus. Methods need a real `#[verus_verify]` on struct and impl.
- Measured on rustc 1.97 stable: an identity stub attribute on a loop statement fails with E0658. Under Verus the file needs `#![feature(proc_macro_hygiene)]`.
- Measured: the form of the Decision verifies (2 verified, 0 errors), and its mutated twin fails with "postcondition not satisfied".
- The `&mut` spec syntax changed in 2026, and older examples fail.
- CI cannot build Verus cheaply (about 7 minutes, release downloads return 403).

## Decision

- All Verus-annotated code lives in `ghidorah-kernel`, a leaf crate that depends only on `ghidorah-spec`.
- `ghidorah-spec` is a std-only proc-macro crate. `#[verus_verify]` and `#[verus_spec]` return their input unchanged. `proof!{}` expands to nothing.
- The kernel `lib.rs` starts with `#![cfg_attr(verus_only, feature(proc_macro_hygiene))]`.
- Imports: `#[cfg(verus_only)] use vstd::prelude::*;` and `#[cfg(not(verus_only))] use ghidorah_spec::{verus_spec, verus_verify, proof};`.
- Every loop carries `#[cfg_attr(verus_only, verus_spec(invariant .., decreases ..))]` directly before `while`, `loop` or `for`.
- `#[cfg(verus_only)]` appears only on `use vstd::prelude::*;` and on `verus! { }` blocks with spec and proof items. Exec code is never cfg-gated.
- Command: `verus --cfg verus_only --no-cheating --crate-type=lib --output-json crates/kernel/src/lib.rs`.
- Kernels: K1 Reader, K2 range math, K3 RangeSet (view `covers`, push rebuilds), K5 fusion table (`fused_pred`, `eval_pred`), K6 budget fit, K7 provenance order. The design drops K4 (abstract undo law), because the clone-stack model test checks the real inverses.
- Each kernel has a negative patch in `verify/negative/<kernel>.patch`. `xtask verify` applies it to a copy and requires a verification error with `verified >= 1`. A compile error does not count.
- Each kernel has a tier-1 test as second evidence (design Section 13.1).
- `xtask verify` writes `verify/results.json` with the Verus commit (ffc9d20), toolchain, z3 4.16.0, argv and `tree_sha256`. The tree hash covers `crates/kernel/src/**`, `crates/spec/src/**` and the argv. Without Verus it reports `skipped`.
- The freshness test warns in plain `cargo test` and fails under `GHIDORAH_REQUIRE_PROOFS=1` (set by `xtask ci` for its child process).
- Each kernel has a time box. A kernel that does not verify in time gets `unproven`, and its tier-1 test carries the gate.

## Alternatives

- Exec code inside `verus! {}` with a cfg gate. Rejected: the verified code and the shipped code then differ.
- `vstd` as a Cargo dependency. Rejected by ADR-0001.
- Property tests only. Rejected: the kernels are small and proofs are cheap. Property tests stay as second evidence.
- Negative twins as full file copies. Rejected in revision 2: a stale copy fails to compile and passes for the wrong reason.

## Consequences

- The verified code is the shipped code. The rest of the workspace never meets the Verus toolchain.
- The kernel crate has a documented exception for `indexing_slicing` and `arithmetic_side_effects` where Verus proves the bounds.
- Production code must use the kernel `RangeSet`. If it is too slow, its structure changes inside the kernel, never in a parallel type.

## Amendment 2026-10-17

- These items are new: the measured loop form, `proof!{}`, the cfg-gated imports, the exact command, negative patches, the tree hash, tier-1 tests per kernel and the K3 view. K5 now owns the shipped fusion table.
