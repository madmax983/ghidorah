# ADR-0010: Decompiler structuring with Phoenix-lite, SAILR-lite, self-check and flat fallback

Status: Accepted for Increment D (amended 2026-10-17). ADR-0018 gates the start.
Date: 2026-10-16
Verified by: AC-073, AC-098a to AC-098c, AC-099 to AC-104b, AC-105a, AC-106a, AC-106b, AC-108, AC-235, AC-236, AC-237

## Context

- On 7,355 Debian functions: SAILR 2,673 gotos, Hex-Rays 6,115, Ghidra 6,575, Phoenix 8,497. Goto-free methods (DREAM, rev.ng) cost faithfulness (research 3.7).
- Raw Ghidra output passes re-execution for only about 20% of functions. Agents treat pseudo-C as truth.
- The structurer is the highest algorithmic risk of the design.
- The line budget (ADR-0018) does not fit the decompiler in the MVP plan.
- Revision 1 printed variable types but had no rule for their effect on code, and large functions had no page form.

## Decision

- The decompiler is Increment D. Design Section 8 holds its full design. It starts only when the measured gate of ADR-0018 passes.
- Goal: few gotos and high faithfulness, not zero gotos. No boolean state variables. The structurer duplicates only tiny exit blocks.
- Phoenix-lite post-order collapse: the 4 short-circuit shapes first, then Seq, IfThen, IfThenElse, Switch; While, DoWhile and endless loops with break and continue. Last resort: one virtual edge per step with a deterministic rule.
- SAILR-lite passes in Increment D: canary removal, per-call-site noreturn, tail calls as `return f()`. Return duplication, loop-inversion cleanup and guard-clause flattening are stretch S31.
- The statement tree is an output view of L1. Passes never edit L1. Folding follows the angr rule (1 def, 1 use, no store, call or memory `Intrinsic` between, no def leaves a loop).
- A runtime self-check compares CFG and AST block traces under 8 seeded branch oracles. A mismatch switches to FLAT output.
- FLAT output (all blocks in address order with labels and gotos) is the fallback when structuring fails, the self-check fails or the budget (`max_nodes` 500 or fuel) runs out.
- Output is machine-addressable: `line_map` with OpIds, line windows with cursors, comments with `line_map` rows, `elided` with reasons, metrics and warnings with remedies.
- A minimal type lattice seeds from prototypes, signatures and agent types, and spreads over copies and phis. The printer shows `v->field` for a pointer to a complete record.

## Alternatives

- A goto-free structurer (DREAM). Rejected: it costs faithfulness.
- The decompiler in the MVP. Rejected by the budget review (ADR-0018).
- FLAT output only. Rejected as the goal, kept as the fallback.
- Type-letter variable names with no type source. Rejected in revision 2.

## Consequences

- Correctness gates: trace equivalence with a FLAT-rate floor, the expression oracle against the L0 interpreter, `line_map` coverage, goto budgets per golden fixture and a fallback-rate floor.
- Some `-O2` output keeps gotos. Metrics report them.
- The idiom table (magic division) and a runtime pass check are stretch items.

## Amendment 2026-10-17

- The decompiler moved to Increment D. Line windows, comments in text, the type lattice and the floors are new. The skeleton view moved to stretch S11.
