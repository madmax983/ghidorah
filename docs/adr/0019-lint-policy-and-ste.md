# ADR-0019: Lint policy and STE enforcement levels

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-010, AC-016, AC-024, AC-025, AC-225

## Context

- The owner standard asks for clippy pedantic and nursery, no `unwrap()`, doc comments on all public APIs and ASD-STE100 text.
- Some nursery lints are noisy. `indexing_slicing` and `arithmetic_side_effects` are noisy in address code. A regex STE checker gives false positives (research 3.10).
- Lint friction costs builder time in a single long session.
- In revision 1, the STE checker lived in `xtask`, which `tools` tests cannot use, and the rules had no IDs and no test corpus.

## Decision

- `[workspace.lints.clippy]`: `all`, `pedantic`, `nursery` (and `cargo` where it applies) at `priority = -1`, denied in CI with `CARGO_BUILD_WARNINGS=deny`. Also denied: `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `dbg_macro`, `allow_attributes_without_reason`, and `print_stdout` and `print_stderr` in library crates.
- Reviewed nursery allowlist (workspace level, each with a reason): `option_if_let_else`, `redundant_pub_crate`, `significant_drop_tightening`, `missing_const_for_fn`, `cognitive_complexity`, `future_not_send`.
- The workspace denies `indexing_slicing` and `arithmetic_side_effects` in parser code (`loader`, `json`, `x86::len`) and in the kernel, with a per-item proof reason.
- `rust`: `unsafe_code = "deny"`, `missing_docs = "deny"`, `unexpected_cfgs` with `cfg(verus_only)`.
- `too-many-lines-threshold = 100`. Decoder and lifter tables live in `tables/` files with a module-level `expect` and a reason.
- `pub(crate)` is the default visibility, so `missing_docs` applies to a small surface.
- The STE checker is a library in `ghidorah-testkit::ste` (WP-02). `xtask ste` wraps it. The `tools` test `ac_024_ste_agent_text` calls it in deny mode for every registered tool, action line, error, warning, hint and the server instructions.
- Rules: STE-1 a procedural sentence (its first word is an imperative from `docs/GLOSSARY.md`) has at most 20 words. STE-2 a descriptive sentence has at most 25 words. STE-3 a paragraph has at most 6 sentences. STE-4 no passive voice (be plus participle). STE-5 no present perfect. STE-6 no word of `docs/ste-banlist.txt` (`would`, `could`, `should`, `ensure`, `utilize`, `via`, `e.g.`, `etc.`, `i.e.`). STE-7 no run of more than 3 nouns. STE-8 no two imperatives joined by "and".
- Counting: a code span counts as one word. A parenthetical counts as one word. A comma enumeration of code spans counts as one word, and so does a list after a label and a colon. The checker checks table cells. It skips headings, fenced blocks and Mermaid.
- `tests/data/ste/{pass,fail}.txt` hold corpus lines with the expected rule IDs (AC-225).
- Deny mode applies to agent-facing text. Warn mode applies to comments and docs, with the reviewed allowlist `docs/ste-allowlist.txt` (AC-025). The checker exempts only `docs/research.md` and `docs/planning/` by path.
- The copyrighted STE dictionary is never shipped. `docs/GLOSSARY.md` lists the approved technical nouns and verbs.

## Alternatives

- Deny mode everywhere. Rejected: false positives in code comments slow the builders.
- Warn mode everywhere. Rejected: agent-facing text is where STE matters most.
- A checker in `xtask` only. Rejected: tests in production crates cannot call it.
- A copy of the STE dictionary. Rejected: copyright.

## Consequences

- Each allowlist entry is visible in review.
- Agent-facing text meets STE strictly from WP-13a on, so descriptions and messages need no late rewrite.

## Amendment 2026-10-17

- The checker moved to `testkit`. Rule IDs, counting rules, the corpus and the exempt paths are new.
