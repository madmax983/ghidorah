# ADR-0025: Unsafe code only in dev-only crates

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-004

## Context

- Unsafe code in a decoder or loader turns hostile input into memory corruption instead of a diagnostic.
- Some test tools need unsafe code: the native `asm!` flag oracle (RWX page) and a counting global allocator.
- In revision 1, in-process capture of fixture leaf functions needed a raw `mmap`, relocation and RIP-relative data access in 400 lines of unsafe code.
- Source code cannot lower `forbid`, so a workspace `forbid` blocks the dev crates.

## Decision

- The workspace sets `unsafe_code = "deny"`.
- Only `ghidorah-oracle` (dev-only) uses `#![expect(unsafe_code, reason = "...")]`. It holds the native flag oracle and the counting allocator. No fixture code runs in the oracle process.
- Leaf-function vectors come from `fixtures/src/leaf_driver.c`, linked with each leaf object at `xtask fixtures build` time.
- `ghidorah-oracle` runs native code only from `xtask oracle`, in child processes, and writes vectors that `cargo test` replays.
- No crate in the dependency closure of the `ghidorah` binary contains `unsafe` (AC-004).
- Coverage-guided fuzzing with sancov (needs unsafe callbacks) is a deferred item.

## Alternatives

- Unsafe code in the decoder for speed. Rejected: memory corruption from hostile input.
- In-process capture of fixture functions. Rejected in revision 2: large unsafe surface and high risk.
- A sancov fuzz crate. Deferred.

## Consequences

- The shipped binary is free of unsafe code.
- Semantic vectors are host-generated evidence with headers that name the host CPU and the generator version.

## Amendment 2026-10-17

- The leaf driver replaces in-process leaf capture. The oracle crate shrinks to about 250 lines.
