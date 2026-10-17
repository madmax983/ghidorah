# Kernel proofs

This directory holds the proof record of `ghidorah-kernel` (design Sections 13.1 to 13.3, ADR-0011).

| File | Content |
|---|---|
| `results.json` | The record of the last `cargo xtask verify` run. |
| `negative/<kernel>.patch` | One hunk that breaks one kernel. Its Verus run must fail. |

## Run the proofs

1. Build Verus with the steps in `CLAUDE.md`.
2. Set `VERUS` to the `verus` binary. Without `VERUS`, the command uses `verus` on `PATH`.
3. Set `VERUS_Z3_PATH` to the z3 binary.
4. Run `cargo xtask verify`.
5. Commit `results.json` with the kernel change.

The command runs Verus one time for each kernel with `--verify-module <module>`.
Then it applies each negative patch to a copy of the kernel in `target/xtask-verify/` and runs Verus again.
A negative run must give `postcondition not satisfied`, `assertion failed` or `precondition not satisfied`.
It must also verify at least one item. A compile error does not count.

Without Verus, the command fails with `status: missing`.
With `GHIDORAH_VERUS_OPTIONAL=1`, it gives `status: skipped` and exit code 0.

## Record

| Field | Content |
|---|---|
| `verus_commit`, `toolchain`, `z3` | The tool versions of the run. |
| `argv` | The Verus command. The program name is `verus` on every host. |
| `tree_sha256` | The tree hash of the proof inputs. |
| `kernels.<name>` | `verified`, `errors`, `spec_items` and `status` of one kernel. |
| `negatives` | `error_kind`, `verified`, `errors` and `ok` of each negative patch. |

The tree hash covers each file under `crates/kernel/src` and `crates/spec/src` in path order.
For each file, the hash takes `file <path>`, a newline, the byte count, a newline and the bytes.
Then it takes `argv`, the Verus command and a newline.
`xtask/src/verify/tree.rs` holds this rule. The kernel test `ac_034_proof_freshness` uses the same file.

A change to a kernel file or to the stub crate makes the record stale.
Then `ac_034_proof_freshness` gives a warning, and it fails under `GHIDORAH_REQUIRE_PROOFS=1`.

## Negative patches

| Kernel | File | Change | Expected error |
|---|---|---|---|
| K1 | `reader/leb.rs` | `leb_scan` accepts an unsigned 10th byte up to 3. | postcondition not satisfied |
| K2 | `range.rs` | `va_to_file` accepts the first address after the file bytes. | postcondition not satisfied |
| K3 | `rangeset.rs` | `insert` does not extend the merged range to the left. | precondition not satisfied |
| K6 | `budget.rs` | `fit_prefix` rejects a prefix with a cost equal to `max`. | postcondition not satisfied |
| K7 | `source.rs` | `may_overwrite` rejects a write of the same rank. | postcondition not satisfied |

Make a new patch with `diff -u` against the current source. Each patch has exactly one hunk.
