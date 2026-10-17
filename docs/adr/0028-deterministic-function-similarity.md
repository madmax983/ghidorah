# ADR-0028: Deterministic function similarity; learned embeddings deferred

Status: Accepted
Date: 2026-10-17
Verified by: AC-238, AC-239, AC-240, AC-241, AC-242, AC-243

## Context

- Agents spend many calls to name functions in stripped binaries. A known function in another binary (an unstripped build, a library, an older version) can give the name.
- Ghidra BSim and similar tools compare per-function feature vectors. Learned function embeddings give strong results in papers, but they need model weights and an inference runtime.
- ADR-0001 allows no third-party crates. Model weights are a large binary input with license questions.
- Revision 2 listed function hashes and clone groups as stretch S23 and BSim-lite as deferred. The owner moved similarity into the MVP in revision 3.
- Output must be deterministic and has no floats (ADR-0012). Hints carry no binary-derived names (ADR-0022).

## Decision

- WP-29 adds `analysis::similar` and tool 23 `func_similar` (design Sections 7.13 and 10.4). The tool is read-only and idempotent and is in the `full` and `readonly` profiles.
- Features per function: normalized L0 opcode n-grams (n = 1 to 3, registers and constants abstracted), CFG shape buckets (blocks, edges, loops, maximum loop depth), two rounds of Weisfeiler-Lehman labels over the CFG, constants with `|v| > 255` that are not image addresses, string content hashes, called import names and a callee count bucket. Feature keys are FNV-1a 64 hashes from `base`.
- Weights: TF-IDF over all functions of all open binaries, in integer fixed-point arithmetic. Score: cosine similarity in thousandths (0 to 1,000).
- Order: score descending, then `binary_id`, then address. No `HashMap` on these paths.
- Explanations: each match lists its top shared features with their share of the score.
- Name proposals: only from a rank-1 match with an `Imported`, `Agent` or `User` name, with a score of at least 800 and a margin of at least 50 over the best match with another name, and only for a query function with a `Default` or `Analysis` name. The `next` hint is a `batch_run` that runs the query again and applies the proposals through a `symbol_rename` reference, with evidence. One `history_undo` reverts it.
- Vectors are derived data with the key `(FuncId, func_epoch)`. The journal never holds them.
- Deferred: learned embeddings, because they need model weights and break the zero-dependency rule.
- Deferred: a bring-your-own-vectors hook (export the per-function feature streams, import external vectors, kNN in the core).
- Function hashes and clone groups (stretch S23) leave the stretch list, because this design covers them. `binary_diff` and FunctionID stay deferred.

## Alternatives

- Learned embeddings in the core, for example a small graph network. Rejected: model weights, an inference runtime and results that differ between hosts.
- Exact function hashes only (S23). Rejected: one changed byte breaks a match, and hashes give no ranking and no explanation.
- A BSim-style signature store on disk. Rejected for the MVP: a second persistent format. Vectors are cheap to build again from the facts.
- Floating-point TF-IDF. Rejected: floats on output paths break ADR-0012, and `ln` can differ between platform math libraries.
- Literal names in the `next` hint. Rejected: hints carry no binary-derived names (ADR-0022). A batch reference carries them instead.

## Consequences

- Agents can name stripped functions from a twin or a library, with evidence that they can check and undo.
- Results depend on the set of open binaries, because the IDF uses all of them. `data.corpus` reports the set.
- The feature stream format is the seam for a later bring-your-own-vectors hook.
