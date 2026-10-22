# ADR-0004: In-memory program database with journal and snapshots; facts versus derived data

Status: Accepted (amended 2026-10-22)
Date: 2026-10-16
Verified by: AC-097, AC-117, AC-120a, AC-120b, AC-120c, AC-123, AC-189a, AC-203, AC-210

## Context

- Ghidra uses a paged B-tree database with physical undo (research 3.1). That is too large for the MVP.
- Claude Code can restart the stdio server at any time. Agent work must survive (research 3.9).
- The planning inputs conflicted. One input persisted only facts above ANALYSIS and re-analyzed on open. Another made each analysis run an undoable Tx. On-demand local analysis made state depend on call order.
- Durability claims need a test method. A process kill keeps the page cache, so it cannot show a missing sync.

## Decision

- `Program` is plain owned data with `BTreeMap` tables per manager. Manager mutators are `pub(crate)`. The only public write path is a Tx guard with a closed `Edit` enum (15 variants) that returns exact inverses.
- Facts: memory, code units, functions, symbols, refs, signatures, types, comments, notes, variable facts, overrides. Derived data: decoded instructions, L0, CFG, IR views, SSA, pseudo-C and similarity vectors. The journal never holds derived data. Bounded caches keyed by `(FuncId, func_epoch)` hold it.
- ANALYSIS facts are a pure function of their inputs: bytes, analyzer versions, analysis config and the higher-rank facts that affect analysis. Their hash is `analysis_inputs_hash`.
- An analysis-affecting edit starts a re-analysis at the start band of the edit (design Section 3.9). Signature edits start at band 800. Other analysis-affecting edits start at band 100. ADR-0016 gives the committed and shadow sets.
- Agents cannot undo analysis runs. They undo their own edits, which starts a new re-analysis.
- Persistence: `bin/<sha256>` (immutable input), `journal.jsonl` (append-only, one checksummed line per committed Tx, one sync per commit, analysis-run markers and `meta` lines instead of analysis facts) and `snapshot.json` (canonical JCS of all facts plus `analysis_inputs_hash`, through temp file, sync, rename and directory sync).
- All file access goes through an `Fs` trait. Tests use `RecordingFs` to check the operation order and `CrashFs` to stop at every operation.
- Open: load the snapshot, replay journal lines after its rev, drop a torn last line with a warning, stop on a corrupt middle line, compare `analysis_inputs_hash` and re-analyze when it differs.
- On-demand local analysis is not in the MVP. Patches are stretch S26.

## Alternatives

- Persistent immutable maps. Rejected: about 1,500 LOC, harder proofs, no benefit over inverse edits for the MVP.
- Each analysis run as an undoable Tx. Rejected: state then depends on the order of edits and runs.
- A Ghidra-style paged B-tree with physical undo. Rejected: too large for the budget.

## Consequences

- State does not depend on the order of edits, undos and analysis calls (AC-097, AC-210).
- Analyzer upgrades improve old projects: a new analyzer version changes `analysis_inputs_hash`, so open re-analyzes.
- A large binary pays a re-analysis from the start band after each analysis-affecting edit. Reads continue on the committed set.
- Agent facts that lose their anchor become orphans with `W_FACT_ORPHANED`. Nothing deletes them.
- `state_hash` (SHA-256 of the JCS fact dump) is the one equality for tests. The session computes it on demand only.

## Amendment 2026-10-17

- Re-analysis starts at a start band, not always from scratch. The `Fs` trait and crash tests are new. Patch edits moved to the stretch list.

## Amendment 2026-10-17 (revision 3)

- SSA and pseudo-C are MVP derived data (ADR-0018). Similarity vectors (ADR-0028) are derived data with the key `(FuncId, func_epoch)` and never enter the journal.

## Amendment 2026-10-22

- The project format version is 2. Each import gets `ext:` and 1 plus the rank of its import ID. So the import order of the loader does not change `state_hash` (AC-189a).
- A version 1 project still opens. The `db::migrate` module maps each old `ext:` address of the snapshot facts and the journal edits to its new address. A write open writes `project.json` at version 2.
- The golden v1 project is frozen. A bless does not write it again (AC-120c).
