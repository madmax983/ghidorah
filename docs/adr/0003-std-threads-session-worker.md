# ADR-0003: Std threads and a single-writer session worker instead of tokio

Status: Accepted
Date: 2026-10-16
Verified by: AC-148, AC-170, AC-172, AC-173

## Context

- tokio is a third-party crate (ADR-0001).
- The MCP stdio server must stay responsive during long analysis, accept cancellation and write only protocol lines to stdout.
- `Program` is large mutable state. Locks on it add complexity and nondeterminism.
- `catch_unwind` cannot catch a stack overflow or an abort (research 3.10).

## Decision

- `ghidorah mcp` has three std threads: a reader (frames stdin lines, 16 MiB cap, handles `notifications/cancelled`), one worker (owns all sessions and projects, runs requests in arrival order) and a writer (the only stdout writer).
- Channels connect the threads. Each in-flight request has an `Arc<AtomicBool>` cancel flag. The worker polls it at fuel checkpoints.
- Long work runs in fuel slices inside the worker (ADR-0016). `Program` needs no locks.
- The worker thread has a fixed 64 MiB stack. All recursion is depth-counted, and graph algorithms are iterative.
- Each request runs under `catch_unwind`. A panic gives `INTERNAL_ERROR` with a crash file. The session then drops the in-memory `Program` and reloads it from snapshot and journal. `Drop` of a Tx does not roll back during a panic.
- `tools::dispatch_with(&Registry, ..)` lets tests inject a panicking tool (AC-148). The shipped registry has no test items.
- A broken pipe on stdout ends the process with exit code 0.

## Alternatives

- tokio or another async runtime. Rejected by ADR-0001.
- One thread for everything. Rejected: no cancellation and no progress during long work.
- One thread per request. Rejected: it needs locks on `Program` and gives a nondeterministic order.

## Consequences

- One request runs at a time. Reads wait while a fuel slice runs. Slices are short (default 2,000,000 units), so the delay is small.
- No async runtime, no executor, no `Send` bounds on `Program`.
- Parallel analysis is deferred. The facts and derived-data split (ADR-0004) keeps it possible later with a deterministic merge.
