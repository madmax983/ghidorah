# ADR-0021: Result envelope, error catalog, budgets and cursors

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-133, AC-134, AC-135, AC-136a to AC-136c, AC-141b, AC-143, AC-214, AC-220

## Context

- Claude Code warns at 10,000 output tokens, caps a result at 25,000 tokens and cuts error text above about 11,000 characters (research 3.9).
- Missing data with no notice leads agents to wrong counts. Stale cursors give duplicate or missing items.
- The planning inputs used several names for the same errors.
- Revision 1 had gaps. The failure envelope had no `next`. Repair fields changed shape per code. Warnings had no catalog. The budget measured one copy of a result that the server sends twice. Every rename broke a `func_list` page.

## Decision

- One envelope for every tool on every surface: `ok`, `binary_id`, `rev`, `session`, `analysis`, `partial`, `data`, `page`, `warnings`, `next` (at most 3 executable calls), `error`. A failure envelope also carries `next` at the top level.
- Frozen error object: `{ code, num, message, hint, retryable, field_path?, candidates?: [{ value, label, id?, addr?, kind? }], candidates_total?, details?, crash_id? }`.
- Repair classes: R (`next[0]` is the complete corrected call), C (choices in `candidates`), H (`next[0]` is a helper call), N (no mechanical repair).
- A frozen `WarningCode` catalog with items `{ code, num, at?, message, remedy? }`.
- Error codes are the frozen catalog of design Section 10.8 (38 live codes, 3 reserved numbers). Cursor codes are `CURSOR_INVALID` and `CURSOR_STALE`. The profile code is `TOOL_NOT_IN_PROFILE`. New: `NO_BINARY_OPEN`, `NOTHING_TO_REDO`.
- The dispatcher applies budgets, not the handlers. `max_chars` covers the whole serialized `tools/call` result, every content block included. Hard cap 60,000 characters. Defaults stay at or below 24,000. Error objects are at most 10,000 characters with 5 candidates plus a total.
- Trimming happens only at item boundaries (kernel K6) and always sets `truncated`, `total`, `next_cursor` and a narrowing hint. `func_get` splits its budget by section weights.
- Keyset cursors hold the args hash and the sort key of the last item. Edits never invalidate them. `CURSOR_STALE` comes only when the boundary item now has another sort key.
- Each analysis run freezes `priority`. `visited` is a live filter.
- Hints and `next` args carry IDs and addresses only, and each must parse with the target tool's `ArgSpec`.

## Alternatives

- Offset cursors staled by table epochs (revision 1). Rejected: every rename broke the most common agent loop.
- A `valid_example` field next to `next`. Rejected: two repair fields with different shapes.
- A budget on the envelope only. Rejected: hosts can show two copies.
- Etags and a compact text block. Moved to stretch S20 and S12.

## Consequences

- One matrix test over every tool and example proves the budget, envelope and error rules.
- The repair robot sends `next[0]` for R codes and never picks a choice.

## Amendment 2026-10-17

- New rules replace the revision 1 rules: the frozen error object, `next` in failures, repair classes, the warning catalog, the whole-result budget, keyset cursors and the frozen priority. Etags moved to stretch S20.
