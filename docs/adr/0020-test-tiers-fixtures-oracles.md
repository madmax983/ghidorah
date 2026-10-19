# ADR-0020: Test tiers, fixtures, oracles, evidence and xtask scope

Status: Accepted (amended 2026-10-17, revision 3, and 2026-10-19)
Date: 2026-10-16
Verified by: AC-018a, AC-018b, AC-018c, AC-020, AC-021, AC-022, AC-224

## Context

- Tests must pass without objdump, gcc, llvm-mc or readelf at run time.
- Native oracles need RWX pages and can kill a test process with a signal.
- An Apache-2.0 repository cannot hold GPL and LGPL binaries (bash, libc).
- Small fixtures give noisy F1 gates (one miss changes F1 by 0.015 on 36 functions).
- A long `cargo test` cuts the number of edit-test loops in a session.
- Revision 1 had gaps. The evidence column had no grammar. Tier 2 had no selection method. Tier 1 ran full T3 and a 50,000-function ELF in debug builds.

## Decision

- Tier 1 is plain `cargo test --workspace`: checked-in fixtures and goldens only, fixed seeds, 2,000 fuzz cases per target, at most 120 s on 4 cores and at most 15 s per test.
- Tier-2 tests carry `#[ignore = "tier2"]`. `xtask ci` runs `cargo test --workspace -- --include-ignored` plus long fuzz runs, full T3, T2 determinism, the 50,000-function ELF, coverage, the hermetic run, proof freshness and benchmarks. It records the time of each test.
- `[profile.test]` sets `opt-level = 1`. `ghidorah-x86`, `ghidorah-ir`, `ghidorah-analysis` and `ghidorah-decomp` use `opt-level = 2` in the dev and test profiles. `ghidorah-decomp` is a normal production crate.
- `testkit::fixture::cached` gives one built fixture per test binary.
- Fixtures: T1 first-party C programs with stripped twins, variants, `O2nv` leaf builds, the rebase pair and adversarial names. T2 a first-party synthetic large program (at least 600 functions). T3 the test executable (300 sampled functions in tier 1, all in tier 2). T4 host binaries only in `xtask oracle`. Total checked-in fixture size at most 3 MiB.
- Oracles run only in `xtask` (`fixtures build`, `golden`, `oracle`). Leaf vectors come from a C leaf driver at fixture build. The native flag oracle runs each form in a child process. `cargo test` replays the vectors.
- Golden headers record the generator version, oracle versions and fixture sha256. `GHIDORAH_BLESS=1` rewrites them, and `bless` prints a per-area count.
- Evidence grammar: `test:<crate>::<fn>@T1|T2`, `cmd:<argv>`, `xtask:<subcommand>#<pointer> <op> <value>` and `record:<file>#<pointer>@sha256=<input>`. `xtask ac` writes `docs/ac-evidence.json` and checks the Needs order of each AC.
- The hermetic run builds with the full `PATH`, then runs the test binaries with a reduced `PATH` and an empty `HOME`.
- xtask commands: `ci`, `cov`, `verify`, `fuzz`, `golden`, `fixtures`, `oracle`, `eval`, `ste`, `bench`, `ac`, `deps`. Workspace gates are cargo integration tests in `xtask/tests/`. Mutation testing is deferred.

## Alternatives

- Tiers through environment variables. Rejected: tests cannot set them in process (ADR-0012), and `#[ignore]` is standard.
- A third-party test runner (nextest). Rejected by ADR-0001.
- Oracles inside `cargo test`. Rejected: host-dependent and flaky.

## Consequences

- The default test run is hermetic and host-independent.
- Oracle results that need host binaries are `record:` evidence, not cargo tests.

## Amendment 2026-10-17

- `#[ignore]` tiers, the evidence grammar, the Needs check, T3 sampling, the opt-levels, the fixture cache, the leaf driver and the per-test cap are new.

## Amendment 2026-10-17 (revision 3)

- `xtask loc` is removed (ADR-0018).
- T1 gets the PE32+ fixtures of WP-30. `xtask fixtures build` makes them offline with `clang --target=x86_64-pc-windows-msvc` and `rust-lld -flavor link`, and the goldens come from `llvm-readobj` and `llvm-objdump` of the pinned toolchain. `PeBuilder` in `ghidorah-testkit` makes malformed variants.
- The `pe_load` fuzz target runs 10,000 fixed-seed cases in tier 1.

## Amendment 2026-10-19

- A `record:` item checks the hash of its named input. The input `tree` compares the `tree_sha256` of the record with the tree hash of the proof inputs. The input `host-<name>` compares the `sha256` of the object at the pointer with the SHA-256 of the host file at its `path`. A missing host file gives `skipped`.
- `xtask ac` without `--run` reports `failed` from `docs/ac-evidence.json`, and it checks each record item again. AC-018b reads this list.
- A run with a list of ACs replaces only the rows of those ACs in the table.
- An `xtask:ac` item reads the table of its own run. The runner writes the table before it runs these items.
- The doc gates AC-023a, AC-023b and AC-027 are in `xtask gates`.
