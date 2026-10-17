# ADR-0018: MVP scope and deferrals

Status: Accepted (amended 2026-10-17, revision 3)
Date: 2026-10-16
Verified by: AC-018a, AC-018b

## Context

- The owner gave a size guide of "about 25,000-35,000 lines of production Rust plus tests" for one long session of AI coding agents.
- Revision 2 turned the guide into a gate: a line ledger (`docs/budget.json`, `xtask loc`, AC-015a to AC-015d), measured triggers, a cut list (Y1 to Y4) and a gate for SSA and the decompiler (Increment D).
- On 2026-10-17 the owner decided (revision 3): SSA and the decompiler, a PE32+ x86-64 loader and function similarity are part of the MVP, and the line count is not a gate.
- The MVP must be complete with no stubs.

## Decision

- MVP scope: design Section 1.2. It includes SSA and the decompiler (WP-18, WP-21, WP-23), the PE32+ x86-64 loader (WP-30, ADR-0029) and function similarity (WP-29, ADR-0028).
- Stretch items: design Section 1.3. No MVP AC depends on them. Each needs its own ADR, and work on one starts only after the last milestone (M9).
- Deferred items: design Section 1.4. Each names its seam in the MVP. No MVP code has a stub for a deferred item.
- Line counts are information only. Design Sections 1.6 and 2.1 keep plan and upper values per crate and per WP for scheduling. No test, xtask command, milestone or WP definition of done checks a line count. There is no `docs/budget.json` and no `xtask loc`.
- AC-015a to AC-015d keep their numbers with the status "Removed in revision 3".

## Alternatives

- Keep the line ledger as a gate with the cut list. Rejected by the owner in revision 3: the gate could remove the decompiler and agent features to meet a number.
- Keep SSA and the decompiler behind a gate (Increment D). Rejected by the owner in revision 3: agents need pseudo-C in the MVP.
- Count production and tests together against 35,000. Rejected in revision 2, and moot in revision 3.

## Consequences

- The plan is about 34,350 production lines (upper 41,530), near the top of the owner range. The numbers inform the pair schedule only.
- No MVP AC depends on a stretch or deferred item.
- Breadth order after the MVP: `binary_diff`, Rust v0 demangler, Go pclntab, Itanium demangler, AArch64, FunctionID, Mach-O, learned similarity embeddings (ADR-0028).

## Amendment 2026-10-17 (revision 2)

- New rules replace the revision 1 rules: the reading, the 27,000 plan, the ledger lines, the file-level re-estimates, the stretch moves, Increment D, the measured triggers and the Y cut list.

## Amendment 2026-10-17 (revision 3)

- The owner decisions of revision 3 replace the revision 2 rules. The line ledger, the measured triggers, the Y1 to Y4 cut list and the Increment D gate are gone. SSA and the decompiler, PE32+ and function similarity are in the MVP. This ADR now records MVP scope only.
