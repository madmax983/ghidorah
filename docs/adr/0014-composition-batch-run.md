# ADR-0014: Composition layer is batch_run

Status: Accepted (hypothesis; the decision rule below confirms or refutes it; amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-175 to AC-185 (all sub-ACs), AC-219

## Context

- Research 3.11 holds no evidence. The design comes from first principles.
- Code execution cut one example from 150,000 to 2,000 tokens, and Hex-Rays reports about 20% fewer tokens with code mode (research 3.2). The saving comes from intermediate results that stay on the server.
- An embedded interpreter is a large second surface with sandbox and determinism risks, and it breaks the zero-dependency rule in practice.
- The planning inputs proposed three designs: `batch_run` (RFC 6901 refs, `pluck`), `plan_run` (`for_each`, `when`, a path grammar) and `edit_batch`.
- Revision 1 had gaps. It did not define the batch output. It allowed globals inside steps and trimmed intermediate steps. The batch tool ran destructive steps under a non-destructive annotation.

## Decision

- One tool, `batch_run`, with steps `{id, tool, args, expect?, claim?}`, at most 32 steps, no nesting, no loops, no conditionals.
- One pointer dialect (RFC 6901 plus a `*` segment) for references, `fields`, guards, CLI `--select` and eval answers. A reference `{ "$ref": step, "ptr": pointer, "partial"?: true }` replaces a whole argument value. A `*` pointer gives map semantics.
- The executor validates the whole batch before any step runs. Each reference is a typed hole, and `OutputShape` checks it. Global arguments go only at the top level. The executor rejects a destructive step and puts the direct call in `next[0]`.
- Every step goes through the normal dispatcher. Step envelopes equal direct-call envelopes.
- The output has one entry per step in input order: `{ id, tool, ok, chars, fuel, data?, error?, page?, warnings?, next? }`, plus `budget_used`. Only returned steps carry `data`.
- A batch with any mutating step is one Tx: all or nothing, one rev, one journal line. `dry_run` returns the planned edit list and rolls back.
- `max_chars` and `max_steps` cover the batch. Steps outside `return` are not trimmed. A reference to a truncated page fails unless it sets `partial`. A read-only batch out of fuel returns `resume` with bindings.
- `edit_batch` does not exist. The CLI JSONL transport is `ghidorah jsonl`.
- Agents with a shell compose calls with `ghidorah call --select` in a script.
- No embedded interpreter, no text query language and no conjunctive queries in the MVP. The relation catalog is the seam for queries.
- Decision rule: the A/B eval confirms this ADR when the batch form saves at least 30% of calls and 20% of characters. This must hold in at least 4 of 5 A/B scenarios. Else a new ADR comes before the composition layer gets new features.

## Alternatives

- `plan_run` with `for_each`, `when` and a path grammar. Rejected: a second grammar and unknown cost before the run.
- An embedded interpreter (Python, Lua, an expression language). Rejected: sandbox, determinism and dependency costs.
- A text query language. Deferred: it must compile 1:1 into `batch_run` and needs A/B data.
- `edit_batch` as a separate tool. Rejected: a mutating `batch_run` covers it.

## Consequences

- No second grammar for IDs, addresses, errors or budgets.
- The executor knows cost and termination before the run.
- What-if dry runs (S18), idempotency keys (S19) and the `lazy` profile (S21) wait for eval data.

## Amendment 2026-10-17

- The `*` pointer replaced `pluck`. The output schema, the globals rule, the destructive-step rule, the trim rule, resume bindings and the decision rule are new. What-if diffs moved to stretch S18.
