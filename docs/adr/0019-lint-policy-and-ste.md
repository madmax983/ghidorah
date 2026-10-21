# ADR-0019: Lint policy and STE enforcement levels

Status: Accepted (amended 2026-10-21)
Date: 2026-10-16
Verified by: AC-010, AC-011, AC-016, AC-024, AC-025, AC-225

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
- Source exceptions: a non-test source file can `allow` or `expect` a group lint in three cases only. The file is a `tables/` file. The lint is `disallowed_types` with a reason. The pair of the file and the lint is a row of the reviewed item list below.
- A lint that the workspace or a crate denies by name is a restriction lint. The source scan of AC-010 does not apply to it.
- No non-test source file can `allow` or `expect` `missing_docs` or a `rustdoc` lint (AC-011).
- `pub(crate)` is the default visibility, so `missing_docs` applies to a small surface.

### Reviewed item list

Each row names one source file, one group lint and its reason. `xtask gates AC-010` checks that each row of `manifest::REVIEWED_EXCEPTIONS` is here.

| File | Lint | Reason |
|---|---|---|
| `crates/analysis/src/tailcall.rs` | `struct_excessive_bools` | Each flag is one condition of the decision table of the module. |
| `crates/base/src/sha256.rs` | `many_single_char_names` | The names `a` to `h` and `w` follow FIPS 180-4. |
| `crates/db/src/progress.rs` | `struct_excessive_bools` | Each flag is one progress column of design Section 3.4. |
| `crates/decomp/src/interp_ast/lower.rs` | `many_single_char_names` | `t` and `f` name the two targets of the branch. |
| `crates/decomp/src/lib.rs` | `struct_excessive_bools` | Each flag switches one pass of `decomp_opts`. |
| `crates/decomp/src/loops.rs` | `many_single_char_names` | The region names follow the schema table of the module doc. |
| `crates/decomp/src/schemas.rs` | `many_single_char_names` | The region names follow the schema table of the module doc. |
| `crates/decomp/src/view/assemble.rs` | `many_single_char_names` | `t` and `f` name the two targets of each branch shape. |
| `crates/ir/src/op.rs` | `cast_possible_truncation` | Each half keeps 32 bits of the value on purpose. |
| `crates/kernel/src/flags.rs` | `fn_params_excessive_bools` | The function takes one value for each flag. The Verus proof covers this signature. |
| `crates/kernel/src/reader/leb.rs` | `cast_possible_wrap` | The value is the two's complement view of the 64 bits. |
| `crates/loader/src/binary.rs` | `struct_excessive_bools` | Each flag is one checksec protection (Section 4.6) or one `DllCharacteristics` bit (Section 4.13). |
| `crates/testkit/src/elf/plan.rs` | `struct_excessive_bools` | One flag selects each optional section of the synthetic ELF file. |
| `crates/tools/src/handlers/note_write/members.rs` | `default_trait_access` | The `tools` crate has no edge to `kernel`, so the `RangeSet` type has no name there. |
| `crates/tools/src/spec.rs` | `struct_excessive_bools` | The four MCP annotations are booleans. |
| `crates/x86/src/decode/special.rs` | `enum_glob_use` | The rows of the special decoder name many mnemonics. |
| `crates/x86/src/lift/rows.rs` | `cast_possible_truncation` | The table has fewer than 255 rows, and a test checks the count. |
| `xtask/src/verify/tree.rs` | `many_single_char_names` | The names `a` to `h` of the SHA-256 rounds follow FIPS 180-4. |
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

## Amendment 2026-10-21

- The AC-010 gate scans the non-test sources for clippy exceptions. The reviewed item list is new.
- The AC-011 gate scans the non-test sources for `missing_docs` and `rustdoc` exceptions.
- The workspace allowlist does not hold `cargo_common_metadata`. Clippy does not apply that lint to a package with `publish = false`.
