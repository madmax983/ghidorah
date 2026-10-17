# ADR-0009: Two-level IR (L0 and L1) with a lazy flag thunk

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-031, AC-067, AC-068a, AC-068b, AC-069a, AC-070, AC-071, AC-207, AC-208

## Context

- Measured: 86-91% of eager x86 flag bits are never read. Block-local fusion with snapshot operands covers 98.0-99.0% of flag reads (research 3.5).
- Eager flags (Ghidra style) give about 10 ops per `cmp`. Fusion at lift time is wrong when an operand changes between the writer and the reader.
- angr, VEX and SLEIGH all shipped flag-table bugs.
- CFG, jump tables and stack tracking do not need SSA.
- gcc 12 and later and clang vectorize at `-O2`. Revision 1 lifted all SSE to `Intrinsic`, so the interpreter stopped on common `-O2` code.
- Revision 1 proved a kernel function that the shipped fusion table did not call.

## Decision

- L0 is a flat VEX-style IR with single-def temps. `Get` and `Put` are the only ops on architectural locations. Registers are full width, XMM registers included. Partial writes use `ZExt` and `Insert`.
- Flags are a lazy thunk `Flags(op, a, b, c)` with snapshot operands. `Cond(cc, Flags(..))` fuses into one compare.
- The kernel owns the fusion table: `fused_pred(op, cc) -> Option<Pred>` and `eval_pred(p, a, b, w)`. Verus proves `x86_cond(cc, flags(op, a, b, w)) == eval_pred(fused_pred(op, cc), a, b, w)` with 12 lemmas (3 ops x 4 widths). `ir::fuse` maps each `Pred` to an `Opc` with one total `match`. A test checks the interpreter result of that `Opc` against `eval_pred` at all widths.
- One semantic module (`x86_flags`, `x86_cond`, `undefined_mask`) serves the lifter, the interpreter, materialization and fusion.
- The lifter handles the SSE move and zeroing subset (`movd`, `movq`, `movaps`, `movups`, `movdqa`, `movdqu`, `movss`, `movsd`, and `pxor`, `xorps`, `xorpd` with one register) as 128-bit loads, stores and copies. The interpreter uses `u128` values.
- Other unsupported instructions lift to `Intrinsic` with declared def and use sets and a memory effect. An `Intrinsic` with a memory operand makes the stack slots that it can touch escape.
- CFG, jump tables, stack tracking and block-local evaluation run on L0. L1 (Braun SSA with SCC phi cleanup, SCCP, copy propagation, DCE) is part of Increment D. Memory is not in SSA. A load never moves across a store, a call or a memory `Intrinsic`.
- The x86 lifter is template-driven (about 14 templates and a mnemonic table).
- `FlagOp::A64*` and `Cc::A64` are reserved, so a later AArch64 crate changes no `ir` pass. ISA crates do not share a carry bit.

## Alternatives

- Eager flags. Rejected: about 10 ops per compare and most flag bits unused.
- Fusion at lift time. Rejected: wrong when an operand changes between writer and reader.
- Full SSE and float semantics. Rejected: cost. The move subset covers the common `-O2` stack copies.
- A proof of a kernel function that the shipped table does not call. Rejected in revision 2: the proof must cover the shipped table.

## Consequences

- The fusion gate (98% of reads) and the exhaustive 8-bit test are measurable. K5 closes the width gap, because the shipped table is the proved table.
- Vector arithmetic stays an `Intrinsic` stop. Leaf subjects also build without the vectorizer.
- Memory SSA and alias-aware forwarding are deferred.

## Amendment 2026-10-17

- The kernel owns the fusion table. The SSE move subset, `u128` values and the `Intrinsic` escape rule are new. L1 moved to Increment D.
