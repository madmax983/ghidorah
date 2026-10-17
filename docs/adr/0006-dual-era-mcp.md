# ADR-0006: Dual-era MCP over stdio

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-169a to AC-169f, AC-171, AC-174

## Context

- MCP 2026-07-28 is stateless: no `initialize`, `server/discover` is required, and each request carries `_meta` protocol keys (research 3.9).
- Legacy clients still use `initialize` with 2025-11-25 or 2025-06-18.
- Measured: Claude Code 2.1.301 probes `server/discover` first and falls back to `initialize`.
- 2025-03-26 allowed JSON-RPC batch arrays. Later versions removed them.
- A server built for one era fails with the other.

## Decision

- Specification snapshot: commit `86f6e0c675afea9a8f233e09b6faf566b126086c` of `https://github.com/modelcontextprotocol/modelcontextprotocol` (2026-10-14), revisions 2025-06-18, 2025-11-25 and 2026-07-28.
- One module (`crates/cli/src/mcp/era.rs`) holds all era rules (design Section 10.13).
- Legacy: answer `initialize` for 2025-11-25 and 2025-06-18. Reply with 2025-11-25 for other requested versions. Do not advertise 2025-03-26. Batch arrays get -32600.
- Modern: serve `server/discover` without a handshake and every request whose `_meta` names 2026-07-28. Missing keys give -32602. Other versions give -32022 with `{supported, requested}`. Every modern result carries `resultType: "complete"`. Legacy results do not.
- Capabilities: tools only. No prompts, resources, logging, completions, tasks or subscriptions.
- No tool declares `outputSchema` in the MVP. `structuredContent` is always an object. Modes `both` and `text` add one text block.
- Cancellation (`notifications/cancelled`) sets a cancel flag. No response follows. Progress notifications are fuel-based and strictly increasing.
- Golden transcripts pin the behavior.

## Alternatives

- Legacy era only. Rejected: 2026-07-28 clients fail.
- Modern era only. Rejected: legacy clients fail.
- Also advertise 2025-03-26 and accept batch arrays. Rejected: more surface for an old version.
- Declare `outputSchema`. Rejected: client errors on shape changes (research 3.9).

## Consequences

- Both client generations connect. `server/discover` must answer fast. Cold start is a tracked metric (AC-171).
- Protocol churn touches one module.
- `max_chars` counts every content block (ADR-0021). The `--content` flag and the eval decide a new default when hosts show both blocks.

## Amendment 2026-10-17

- The ADR now names the specification commit and URL.
