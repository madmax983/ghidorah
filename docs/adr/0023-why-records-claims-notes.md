# ADR-0023: Why-records, three-valued claims and one note store

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-094, AC-159a, AC-159b, AC-204a, AC-204b

## Context

- Decompiler output is not ground truth. Agents need to check claims, not only read output (research 3.2).
- An empty result from an incomplete call graph reads as "nothing calls X". That is the most dangerous agent error.
- A GhidraMCP study found lost context and inconsistent renames. Bookmarks and agent notes overlap in purpose.
- ReSym reached its best symbol-recovery results from relational facts (research 3.2).
- In revision 1, no tool recorded "this call goes to X", so claims about indirect calls stayed `unknown` forever.

## Decision

- Every ANALYSIS fact has a `Why { rule, premises }`. `AnalysisCtx` insert functions take it as a required argument, so the compiler enforces it. Rule codes are a closed enum with a doc line each.
- `fact_check` evaluates claims from a relation catalog of 10 atoms with verdicts `supported`, `refuted` or `unknown`, plus evidence and an absence basis. A negative verdict is `refuted` only when it is sound.
- `func_edit set_call_targets` records the targets of an indirect call. Relations treat that site as resolved.
- `fact_check { explain }` returns the why tree of any fact ID. Value slices of `op:` IDs are stretch S29.
- Notes, bookmarks, hypotheses, findings, todos and named sets are one store. A hypothesis keeps the status that the agent sets. Living hypotheses are stretch S14.
- The same atoms serve `batch_run` claim guards and eval answer checkers.

## Alternatives

- Free-text explanations. Rejected: not machine-readable.
- Two-valued claims. Rejected: they turn incomplete data into a false "no".
- A separate bookmark store. Rejected: two stores with one purpose.

## Consequences

- Agents can ask "why does this function exist" and get a machine-readable answer.
- The relation catalog is the seam for a later conjunctive query engine.
- About 600 LOC for why-records, claims and notes. These are never cut (cut Y4 removes only claims).

## Amendment 2026-10-17

- `set_call_targets`, the 10-atom catalog (`returns_const` moves to Increment D, `emu_returns` to stretch S8) and the stretch moves of living hypotheses and value slices are new.
