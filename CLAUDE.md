# CLAUDE.md

This file gives the working rules for agents in the ghidorah repository.
Read `docs/design.md` Sections 1, 2 and 14 before you change code.
Revision 3 decisions of the owner apply over the design text. SSA and the decompiler are part of the MVP. The owner removed the line-count ledger: there is no `xtask loc`, no `docs/budget.json` and no AC-015.

## Commands

| Task | Command |
|---|---|
| Format | `cargo fmt --all` |
| Format check | `cargo fmt --all -- --check` |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` |
| Tier-1 tests | `cargo test --workspace` |
| Tier-2 tests | `cargo test --workspace -- --include-ignored` |
| Docs | `RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps` |
| Static gates | `cargo xtask gates [AC-nnn ..]` |
| Crate graph | `cargo xtask deps` |
| Coverage gate | `cargo xtask cov` |
| CI steps and test times | `cargo xtask ci [--tier2] [--steps fmt,clippy,doc,offline_build,tier1,tier2,test_times]` |
| STE check of docs and comments | `cargo xtask ste` |
| AC table check | `cargo xtask ac` |
| AC evidence run | `cargo xtask ac --run [--tier2] [AC-nnn ..]` |
| Kernel proofs | `VERUS=<verus> VERUS_Z3_PATH=<z3> cargo xtask verify` |
| Fixture build | `cargo xtask fixtures build [--check]` |
| Fixture checks | `cargo xtask fixtures check` |
| T2 source | `cargo xtask fixtures gen-large` |
| Golden bless | `cargo xtask golden bless [cargo test args]` |
| Golden headers | `cargo xtask golden headers` |
| x86 goldens and their tier-2 oracles | `cargo xtask golden x86` |
| Native semantic vectors (host CPU) | `cargo xtask oracle semantics [--check]` |
| Host bash and libc boundary record (AC-066) | `cargo xtask oracle bash` |

- Each xtask command prints one JSON object on stdout. The exit code is 0 for `ok: true`, 1 for `ok: false` and 2 for an error.
- Set `GHIDORAH_VERUS_OPTIONAL=1` to get `status: skipped` from `xtask verify` when Verus is missing.
- Set `CARGO_BUILD_JOBS=2` when other agents share the CPUs.
- Cargo prints `profile package spec .. did not match any packages` until `ghidorah-analysis` and `ghidorah-decomp` exist. This warning does no harm. Keep the profile entries.

## Gates

A WP is complete when all of these pass:

1. `cargo fmt --all -- --check`.
2. `cargo clippy --workspace --all-targets -- -D warnings`.
3. `cargo test --workspace`.
4. `cargo xtask gates`.
5. `cargo xtask cov`. Line coverage is at least 85% for the workspace, 90% for each core crate and 95% for `kernel`. The core crates are `json`, `loader`, `x86`, `ir`, `db`, `analysis`, `decomp` and `tools`. The gate applies from the first WP that adds code to a crate.
6. `cargo xtask ste` with no new finding.
7. `cargo xtask ac` with an empty `grammar`, `order` and `missing` list.

CI (`.github/workflows/ci.yml`) runs three jobs: `tier1`, `tier2` and `verus`.

## Code rules

- Use the standard library and workspace crates only. No third-party crate can enter the build. `Cargo.lock` has no `source` entry.
- Non-test code has no `unwrap()`, `expect()`, `todo!`, `unimplemented!` or `dbg!`. Comments hold no stub markers.
- Every public item has a doc comment. A function that returns `Result` has a `# Errors` section.
- Output paths use `BTreeMap`, `BTreeSet` or a sorted `Vec`. `clippy.toml` bans `HashMap`, `HashSet` and `RandomState`.
- An internal lookup that never reaches output can use a hash type with `#[expect(clippy::disallowed_types, reason = "..")]`.
- Use newtypes for IDs. Write each error enum by hand with `Display` and `std::error::Error`.
- Bound each loop that reads untrusted input. Use checked arithmetic on file values. Hostile input never causes a panic.
- Keep each non-table, non-test source file at 600 lines or fewer.
- Put unit tests in a separate `tests.rs` file with `#[cfg(test)] mod tests;`.
- No crate calls `std::env::set_var` or `std::env::remove_var`. The `cli` crate reads each `GHIDORAH_*` variable once into `RunConfig`.
- Pure core crates do not use `std::fs`, `std::net`, `std::process`, `std::env` or `SystemTime`. They are `kernel`, `base`, `json`, `loader`, `x86`, `ir`, `types`, `analysis` and `decomp`.
- Parser crates (`loader`, `json`, `x86::len`) and `kernel` deny `clippy::indexing_slicing` and `clippy::arithmetic_side_effects` in their own `lib.rs`.
- A binary that prints sets `#![allow(clippy::print_stdout, reason = "..")]` in its `main.rs`.
- Test files can set `#![allow(clippy::expect_used, reason = "..")]` for helpers outside `#[test]` functions.

## Manifests

- Each package `Cargo.toml` takes `version`, `edition`, `rust-version`, `license` and `publish` from the workspace with `.workspace = true`.
- Each package sets `[lints] workspace = true`. The root `Cargo.toml` holds the lint policy of ADR-0019.
- Add no `allow` entry outside the reviewed allowlist of ADR-0019. `cargo xtask gates AC-010` checks it.
- A new crate edge needs a design change first. Then add one line to `ALLOWED` in `xtask/src/dag.rs`.
- Run `cargo xtask deps` after each edit of `ALLOWED`. It writes `docs/architecture/crates.mmd` again.
- Every package can take `ghidorah-testkit` as a dev-dependency. Only `ghidorah-loader` can take `ghidorah-oracle`.

## TDD process

1. SPEC: write the contract first. Examples are spec tables, golden inputs and doc comments with `# Errors`.
2. PROOF (Verus kernel work only): write `requires`, `ensures` and invariants before the exec body.
3. RED: write the tests of the WP's RED table, plus one test per AC that it closes. Commit `red(WP-nn): <summary>` with the failing test names in the body.
4. GREEN: write the smallest correct code that passes. Commit `green(WP-nn): <summary>`.
5. REFACTOR: clean up with all tests green. Commit `refactor(WP-nn): <summary>`.

- A test that proves an AC has the name `ac_<nnn><letter>_<slug>`.
- A bug fix starts with a failing test `regress_<slug>`. Its commit subject starts with `fix:`.
- Tier-2 tests need gcc, objdump, clang or a long run. They carry `#[ignore = "tier2"]`.
- Tier-1 tests use checked-in files only. Each tier-1 test takes at most 15 s.

## WP and register rules

- Each WP creates the skeleton of the crate that it owns. The member glob `crates/*` finds it, so the root manifest needs no edit.
- Shared lists take one line per item. A WP adds its lines in one final register commit.
- Inside a pair, the second WP rebases its register commit after the first WP merges.
- A new xtask command adds `pub mod <name>;` to `xtask/src/lib.rs` and one arm to `dispatch` in `xtask/src/main.rs`.
- `PAIRS` in `xtask/src/ac.rs` holds the merge order of the WPs. `cargo xtask ac` uses it for the Needs check (AC-018c).
- `PACKAGES` in `xtask/src/workspace.rs` holds the packages of design Section 2.1. A package outside this table fails AC-001a.

## Bless procedure

- `GHIDORAH_BLESS=1` tells `testkit::golden` to write golden files again.
- Run `GHIDORAH_BLESS=1 cargo test -p <crate>`. Then read each changed golden file in `git diff`.
- Commit the golden files with the code change that changes them.
- No test sets the variable in its own process (ADR-0012).

## STE rules for comments and docs (ADR-0019)

- Write ASD-STE100 Simplified Technical English.
- An instruction has at most 20 words. A description has at most 25 words. A paragraph has at most 6 sentences.
- Use the active voice and the simple present tense. Do not use the present perfect.
- Write one instruction in each sentence. Do not join two instructions with "and".
- Do not use a word of `docs/ste-banlist.txt`. Write "make sure" for that meaning.
- Do not put more than 3 nouns in a row.
- Use the technical words of `docs/GLOSSARY.md`.
- Agent-facing text uses deny mode (AC-024). Comments and docs use warn mode with `docs/ste-allowlist.txt` (AC-025).

## Verus hybrid rules (ADR-0011, design Section 13.2)

- All Verus code lives in `ghidorah-kernel`. `ghidorah-spec` gives the stub attributes `#[verus_verify]` and `#[verus_spec]` and the macro `proof!{}`.
- `crates/kernel/src/lib.rs` starts with `#![cfg_attr(verus_only, feature(proc_macro_hygiene))]`.
- Import with `#[cfg(verus_only)] use vstd::prelude::*;` and `#[cfg(not(verus_only))] use ghidorah_spec::{verus_spec, verus_verify, proof};`.
- Put `#[cfg_attr(verus_only, verus_spec(invariant .., decreases ..))]` directly before each `while`, `loop` or `for`. Stable rustc rejects a stub attribute on a loop statement (E0658).
- Put `spec fn` and `proof fn` items in `#[cfg(verus_only)] verus! { .. }` blocks. Never put a cfg gate on exec code.
- `vstd` is never a Cargo dependency (AC-005).
- Run `verus --cfg verus_only --no-cheating --crate-type=lib --output-json crates/kernel/src/lib.rs`.
- A postcondition on `&mut` uses the 2026 syntax `*old(x)` and `*final(x)`:

```rust
#[verus_spec(r =>
    requires
        *old(pos) <= buf@.len(),
    ensures
        *final(pos) <= buf@.len(),
        r.is_some() ==> *final(pos) == *old(pos) + 1,
        r.is_none() ==> *final(pos) == *old(pos),
)]
pub fn read_u8(buf: &[u8], pos: &mut usize) -> Option<u8> {
    let b = *buf.get(*pos)?;
    *pos += 1;
    Some(b)
}
```

## Verus build steps

Verus is not a crate. The CI job `verus` builds it from source and caches the result with a key that holds the commit.

1. Fetch commit `ffc9d20fee64da92cb037be195b467dd321ae4e3` (`ffc9d20`) of `https://github.com/verus-lang/verus`.
2. Run `rustup toolchain install 1.98.1 --profile minimal --component rustc-dev,llvm-tools,rust-std,cargo,rustfmt`.
3. Download the wheel `z3_solver-4.16.0.0` with `pip download z3-solver==4.16.0.0 --no-deps --only-binary=:all:`.
4. Extract `z3_solver-4.16.0.0.data/data/bin/z3` from the wheel to `source/z3` in the Verus tree.
5. In `source`, run `cargo build --release`.
6. In `source`, run `cargo run --release -p cargo-verus -- build --release --manifest-path vstd/Cargo.toml`.
7. Set `VERUS` to `source/target-verus/release/verus` and `VERUS_Z3_PATH` to `source/z3`.
8. Run `cargo xtask verify` (WP-03). It writes `verify/results.json`.

The build takes about 7 minutes on 4 cores.
