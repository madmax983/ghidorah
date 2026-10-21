# Architecture decision records

Each ADR uses this template:

```text
# ADR-NNNN: Title

Status: Accepted | Accepted (amended YYYY-MM-DD) | Superseded by ADR-NNNN
Date: YYYY-MM-DD
Verified by: AC-nnn, AC-nnn

## Context
## Decision
## Alternatives
## Consequences
## Amendment YYYY-MM-DD   (only when the ADR changed)
```

A change to an accepted decision is a new ADR or an amendment section with a date. `docs/design.md` refers to ADRs by number. Appendix A of the design lists the planning conflicts that these ADRs resolve. Test `ac_023b_adr_sections` checks that every ADR has `## Alternatives` and a `Verified by:` line.

| ADR | Title | Status | Decision in one line |
|---|---|---|---|
| [0001](0001-zero-third-party-dependencies.md) | Zero third-party dependencies | Accepted (amended) | Std only; only Section 2.1 packages; no patch, replace or source tables; offline builds. |
| [0002](0002-hand-written-error-enums.md) | Hand-written error enums | Accepted (amended) | Manual `Display` and `Error` per crate; frozen `ErrorCode`, `WarningCode` and `DiagCode` catalogs. |
| [0003](0003-std-threads-session-worker.md) | Std threads and a session worker | Accepted | Reader, worker and writer threads; one worker owns all state; no tokio. |
| [0004](0004-program-db-journal-snapshot.md) | Program DB, journal and snapshots | Accepted (amended) | In-memory tables, Tx guard, JSONL journal, JCS snapshots through an `Fs` trait; re-analysis from start bands; SSA, pseudo-C and similarity vectors are derived data. |
| [0005](0005-one-tool-registry.md) | One tool registry | Accepted (amended) | 23 tools registered per file generate every surface; one vocabulary; profiles are data. |
| [0006](0006-dual-era-mcp.md) | Dual-era MCP | Accepted (amended) | Legacy `initialize` and stateless 2026-07-28 in one module; spec commit `86f6e0c`. |
| [0007](0007-hex-addresses-and-input-grammar.md) | Hex addresses and input grammar | Accepted (amended) | Hex strings out; ordered name resolution with a `sym:` escape; a target-resolution table. |
| [0008](0008-stable-id-grammar.md) | Stable ID grammar | Accepted (amended) | Frozen ID kinds and text forms, `sym:`, `ext:` and the PE forms `imp:<dll>!<name>` and `exp:#<ordinal>` included; IDs never change after a rename. |
| [0009](0009-two-level-ir-lazy-flags.md) | Two-level IR with lazy flags | Accepted (amended) | L0 with a flag thunk; the kernel owns the fusion table; SSE move subset; L1 SSA in the MVP. |
| [0010](0010-decompiler-structuring.md) | Decompiler structuring | Accepted (amended) | In the MVP: Phoenix-lite plus SAILR-lite, self-check, FLAT fallback, line windows, type lattice. |
| [0011](0011-verus-hybrid-pattern.md) | Verus hybrid pattern | Accepted (amended) | Measured loop form, `proof!{}`, negative patches, tree-hash freshness, tier-1 second evidence. |
| [0012](0012-deterministic-output.md) | Deterministic output rules | Accepted (amended) | No HashMap on output paths, fuel not time, no floats, `RunConfig`, no `set_var`, relative paths. |
| [0013](0013-source-priority-agent-rank.md) | Source priority with an AGENT rank | Accepted | Default 1 < Analysis 2 < Agent 3 < Imported 4 < User 5; the journal records forced overwrites. |
| [0014](0014-composition-batch-run.md) | Composition layer is `batch_run` | Accepted (hypothesis, amended) | One pointer dialect with `*`, typed refs, one Tx per mutating batch, no destructive steps; a decision rule. |
| [0015](0015-offline-eval-harness.md) | Offline evaluation harness | Accepted (amended) | Frozen questions (one `pe` append by WP-30) and held-out intents; floors with baselines and a bless log; robots and lints against self-grading. |
| [0016](0016-synchronous-fuel-sliced-analysis.md) | Synchronous fuel-sliced analysis | Accepted (amended) | `analysis_run` resumes by fuel; committed and shadow sets; full analysis on load. |
| [0017](0017-undo-as-forward-commits.md) | Undo as forward commits | Accepted (amended) | Forward undo and redo commits on one linear stack per session. |
| [0018](0018-mvp-scope-and-loc-rule.md) | MVP scope and deferrals | Accepted (amended) | MVP scope with SSA, the decompiler, PE32+ and similarity; stretch and deferred lists; line counts are information only. |
| [0019](0019-lint-policy-and-ste.md) | Lint policy and STE levels | Accepted (amended) | Pedantic and nursery with an allowlist; STE checker in `testkit` with rule IDs; deny for agent text. |
| [0020](0020-test-tiers-fixtures-oracles.md) | Test tiers, fixtures, oracles and evidence | Accepted (amended) | `#[ignore]` tiers, evidence grammar with a Needs check, first-party ELF and PE fixtures, oracles only in `xtask`. |
| [0021](0021-envelope-errors-budgets-cursors.md) | Envelope, errors, budgets and cursors | Accepted (amended) | Frozen error object with repair classes; whole-result budget, cap 60,000; keyset cursors. |
| [0022](0022-binary-text-and-project-safety.md) | Binary text and project safety | Accepted (amended) | One `BinText` shape; IDs only in hints; path roots; projects outside the working tree. |
| [0023](0023-why-records-claims-notes.md) | Why-records, claims and notes | Accepted (amended) | Required `Why` on analysis facts; three-valued claims over 10 atoms; one note store. |
| [0024](0024-closed-world-analyzers-and-seams.md) | Closed-world analyzers and seams | Accepted (amended) | Closed enum with per-file registration; the agent is the plugin; no prologue gap fill. |
| [0025](0025-unsafe-code-policy.md) | Unsafe code policy | Accepted (amended) | `unsafe` only in the dev-only oracle crate; leaf vectors from a C driver. |
| [0026](0026-std-only-benchmark-harness.md) | Std-only benchmark harness | Accepted | Median of 31 samples against `perf/budget.json`; tier 2 only. |
| [0027](0027-coverage-measurement.md) | Coverage measurement | Accepted (amended) | `llvm-tools` instrument-coverage with a per-crate line gate from `xtask/src/cov.rs`; region coverage reported only. |
| [0028](0028-deterministic-function-similarity.md) | Deterministic function similarity; learned embeddings deferred | Accepted | Explainable integer TF-IDF feature vectors and name proposals in the core; learned embeddings and a vector import hook deferred. |
| [0029](0029-pe32plus-in-the-mvp.md) | PE32+ in the MVP | Accepted | PE32+ x86-64 loader with loader-faithful mapping, IAT names, `.pdata` seeds and MS x64; PE32 and other machines unsupported. |
