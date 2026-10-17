# ADR-0013: Source-type priority lattice with an AGENT rank

Status: Accepted
Date: 2026-10-16
Verified by: AC-033, AC-121, AC-163b

## Context

- Ghidra gives AI the same priority as ANALYSIS (both 2). A new analysis run can then overwrite AI names (research 3.1).
- Research 5.2 asks: is AGENT equal to ANALYSIS or above it? Does each session get its own source?
- No measurement supports either order. This is a design decision, not evidence.

## Decision

- Ranks: `Default` 1 < `Analysis` 2 < `Agent` 3 < `Imported` 4 < `User` 5. Persisted numbers never change.
- A write succeeds when its rank is at least the current rank. An `Agent` write over an `Imported` fact needs `force: true`, and the journal records it. Other lower-rank writes fail with `BLOCKED_BY_HIGHER_PRIORITY_SOURCE`, the current value and its source.
- Every fact carries `{source, tx, session, force}`. Session labels are for attribution, filters and the undo scope, not for rank.
- MCP and CLI calls write as `Agent` by default. `ghidorah call --source user` writes as `User`.
- When analysis disagrees with an `Agent` override, the override stays and the function gets `W_AGENT_OVERRIDE_CONFLICT` with the analysis value.
- Kernel K7 proves the write rule.

## Alternatives

- AGENT equal to ANALYSIS (Ghidra AI = 2). Rejected: re-analysis can erase agent work.
- One source per session. Rejected: rank must not depend on a free-text label.
- AGENT above IMPORTED. Rejected: agents then replace the binary's own symbols with no notice.

## Consequences

- Re-analysis never erases agent work. Agents cannot replace the binary's own symbols with no notice.
- A wrong agent guess persists until undone. The conflict caveat, rename evidence and `history_undo` make it visible and reversible.
