# ADR-0017: Undo and redo as forward commits

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-116a to AC-116d, AC-128b

## Context

- A redo stack needs truncation rules and special cases for snapshots, cursors and change feeds.
- Agents need to know who changed a fact, when and why, across sessions.
- Ghidra uses a linear undo stack with named transactions (research 3.9).
- Revision 1 said "undo the latest Tx". A second undo then undid the first undo. An agent was able to undo another session's edit with no notice.

## Decision

- `history_undo` appends a new Tx with the inverse edits and `undo_of`. Redo appends the original edits again with `redo_of`. `rev` only increases. The journal never gets shorter.
- One linear stack per session label. Each original Tx is an entry with the state `applied` or `undone`.
- `history_undo {}` reverts the most recent applied entry of the caller's session. `session: "*"` widens the scope.
- `redo: true` re-applies the most recent undone entry of the scope, only when the scope committed no original Tx after that undo. Else `NOTHING_TO_REDO`.
- `count: n` applies the rule n times as one forward commit.
- Selective undo of an older Tx works when no later applied Tx touched the same fact keys. Else `CONFLICT` with the later Tx IDs.
- An agent undo of a `source: user` Tx needs `force: true`.
- The MCP default session label is `mcp-<k>` per process and binary. Every envelope echoes it.
- `history_list { since_rev }` reads the journal and returns coalesced changes and analysis-run markers. It never expires. Blame (`history_list { id }`) is stretch S22.

## Alternatives

- A redo stack with truncation. Rejected: special cases for snapshots and cursors.
- One global undo stack. Rejected: undo of another session's edit with no notice.
- Physical undo (Ghidra buffers). Rejected: too large for the MVP.

## Consequences

- The catalog needs no `CHANGES_EXPIRED` or `FULL_RESYNC_NEEDED` code.
- The model-based undo test (undo all gives the initial `state_hash`) still holds, because inverses are exact.
- Journals grow with undos. Snapshots keep open time bounded.

## Amendment 2026-10-17

- The per-session linear stack, `NOTHING_TO_REDO`, the user-Tx force rule and the default session labels are new. Blame moved to stretch S22.
