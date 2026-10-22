# ADR-0016: Synchronous fuel-sliced analysis with committed and shadow sets

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-092, AC-172, AC-173, AC-203, AC-209, AC-211

## Context

- Long analysis can exceed client timeouts. The research proposed `analysis_start` plus `job_status` polling.
- Job handles add a state machine, a tool, background work and nondeterministic interleaving.
- MCP tasks changed in 2026-07-28 and are not a stable base.
- Revision 1 did not say what reads see during a re-analysis that runs out of fuel, and `binary_load` ran only triage.

## Decision

- `analysis_run { until, max_steps }` runs synchronously in fuel slices and returns `{ state: complete | budget_stopped | stale, resume }`. The agent calls it again to continue.
- Each program has `analysis = { committed, shadow }`. The first analysis after a load publishes into `committed` once at the end of each call (amendment 2026-10-22). A re-analysis builds `shadow` from the start band of the edit and swaps it in with one `ReplaceAnalysis` commit at completion.
- Reads always use `committed`. While a shadow exists, reads carry `partial: true`, `analysis.state: "stale"` and `W_ANALYSIS_STALE`.
- A restart drops the shadow and starts it again, because the journal holds only completion markers.
- `binary_load` runs `full` analysis by default, with a default `max_steps` that completes every T1 and T2 fixture.
- The server instructions say: "If partial is true, call analysis_run."
- With a `progressToken`, the server sends progress notifications per fuel slice. `notifications/cancelled` stops the run at the next fuel checkpoint.
- Budget-slicing invariance is a property test: repeated `run(k)` equals one unlimited run. A fuel-stopped edit followed by `analysis_run` equals one unlimited run.

## Alternatives

- Job handles with `job_status` polling. Rejected: a state machine and background work.
- MCP tasks. Rejected: unstable across revisions.
- Reads from a partial new set. Rejected: results then depend on where the slices stop.

## Consequences

- No `job_status` tool, no background thread work, no job IDs.
- Reads stay consistent during a re-analysis. They show the old committed set with a stale flag.
- Large binaries need several `analysis_run` calls. Each call has a fuel bound and reports progress.

## Amendment 2026-10-17

- The committed and shadow sets, start bands, the restart rule, the default `full` load and the instruction line are new.

## Amendment 2026-10-22

- A call publishes the first analysis once at its end: at completion, at a stop (fuel, cancel, `max_ms`) or after an error. The engine holds the publish during the fuel slices of the call (`Scheduler::set_hold`, `Scheduler::flush`).
- Reason: each publish builds and commits the whole analysis set. A load in about 20 slices made 20 sets and 20 run lines. Measured on libsystemd.so.0: 10.4 s to 2.6 s. The facts are the same.
- No read occurs between the slices of one call, so no read sees a different set. Progress notifications still fire per slice. A cancel or a stop still leaves a readable partial set.
- One call now makes one revision and one run line, not one for each slice.
