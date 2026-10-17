# ADR-0018: MVP scope, deferrals and the line budget

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-015a, AC-015b, AC-015c, AC-015d

## Context

- The owner budget is "about 25,000-35,000 lines of production Rust plus tests", for one long session of AI coding agents.
- Revision 1 took the most generous reading and planned 33,200 production lines (95% of the 35,000 ceiling), with no line for tests.
- A file-by-file review found three low estimates: `tools` (4,300 against 7-9k), `db` (3,200 against 4.5-5k) and `analysis` (4,400 against 6k or more).
- Reference sizes also suggest low estimates (Phoenix 3,766 lines, LuaJIT C parser 1,934, Itanium demangler 6-12k).
- Revision 1 tied its large cut list to an owner answer that cannot arrive during the session.
- The MVP must be complete with no stubs.

## Decision

- Reading: the budget counts production lines. Test lines have their own capped line in `docs/budget.json`: at most 1.0 times the production lines (target 0.8). Tables and data: at most 4,500. Tooling: at most 6,000.
- Plan: at most 27,000 production lines, more than 20% under the 35,000 ceiling. The ceiling stays a hard gate. Each crate has a plan value and an upper value (design Section 2.1). Each WP has at most 1,800 production lines.
- Counting rule: non-blank, non-comment lines under `crates/*/src` of production crates. `tests.rs` files and `crates/*/tests` count as tests. `tables/*.rs` and embedded data files count as tables. Dev crates count as tooling.
- Scope cuts in revision 2: the decompiler and L1 SSA form Increment D. Items S8 to S31 of design Section 1.3 move to the stretch list. Examples: patching, `emu_run`, etags, idempotency keys and the skeleton view.
- Measured triggers: at M3 and M5, `xtask loc` projects the total from measured lines. Trigger 1: the M3 burn is above 110% of its plan (21,800 lines). Trigger 2: the projection is above 32,000. A trigger applies cuts Y1 to Y4 in order (design Section 1.6). No trigger waits for an owner answer.
- Increment D gate: at M5, Increment D starts only when the projection plus its 4,650 planned lines (times the measured overrun ratio) is at most 33,000.
- The owner can later rule that tests count inside 35,000. Then an ADR amendment drops Increment D, applies Y1 to Y4 and caps tests at 0.6 times production.
- Stretch items need their own ADR and free budget after M7.

## Alternatives

- Count production and tests together against 35,000 now. Rejected for the plan: about 19,000 production lines leave no decompiler, no C types and no claims. The amendment path above keeps this option open.
- Keep the 33,200-line plan and cut on an owner answer. Rejected: it blocks on an answer and has no slack.
- Keep the decompiler in the MVP and cut the agent surface. Rejected: the agent surface is the owner's first priority.

## Consequences

- No MVP AC depends on a stretch item or on Increment D.
- The plan has slack for estimate error, and the triggers act on measurement.
- Breadth order after the MVP: Increment D (if its gate failed), PE with `.pdata`, `binary_diff`, Rust v0 demangler, Go pclntab, Itanium demangler, AArch64, FunctionID, Mach-O, BSim-lite.

## Amendment 2026-10-17

- New rules replace the revision 1 rules: the reading, the 27,000 plan, the ledger lines, the file-level re-estimates, the stretch moves, Increment D, the measured triggers and the Y cut list.
