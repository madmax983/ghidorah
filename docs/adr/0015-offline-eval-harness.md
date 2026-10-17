# ADR-0015: Offline evaluation harness measures the tool surface

Status: Accepted (floors fixed; baselines from the first run; amended 2026-10-17, revision 3)
Date: 2026-10-16
Verified by: AC-153b, AC-195, AC-196a, AC-196b, AC-197, AC-198a, AC-198b, AC-199, AC-200, AC-226 to AC-230

## Context

- Research 3.11 holds no evidence. No LLM runs in CI.
- External numbers (20% token saving, 72% to 90% with examples, 60% to 85% with a workflow instruction, 10-15% function coverage in a GhidraMCP study) are single vendor reports, not baselines.
- The same builders write the tools, the descriptions and the tests, so self-graded metrics can pass by construction.
- In revision 1, a fixed gate and a "no regression" rule disagreed. A bless was able to hide a regression.

## Decision

- Crate `ghidorah-eval` (dev-only) measures the tool surface with deterministic, ground-truth metrics (design Section 12.4).
- WP-06 freezes the questions and their answers (from the C sources) and the intents before any tool description exists. A hash lock guards the questions and the held-out half of the intents. One exception: WP-30 appends the `pe` question group once (revision 3 amendment).
- An argument-provenance lint checks that every scripted argument comes from the question, the schema, the instructions or an earlier response.
- A hint-follower robot measures whether hints alone reach the evidence. Abstain scenarios check that the surface does not overclaim. A restart scenario checks resume after a server restart.
- Scenario files reuse the `batch_run` guard grammar, so there is one assertion language.
- Choice codes are never resolved by the repair robot. Success means the candidates contain the true target.
- `eval/thresholds.json` holds `{ floor, baseline, tolerance }` per metric. The gate is `value >= max(floor, baseline - tolerance)`, or `value <= baseline x 1.10` for cost. Only an ADR amendment lowers a floor. `xtask eval --bless` refuses to lower a floor and appends each change to `eval/bless-log.jsonl`.
- Floors: discoverability 0.70, context-reset recall 0.60, survey fact recall 0.60.
- WP-26 calibrates `chars_per_token` once and stores it.
- The project keeps recorded live sessions as regression transcripts. The live-LLM runner is a deferred item.

## Alternatives

- A live-LLM eval in CI. Rejected: network access, cost and nondeterminism.
- Fixed thresholds only. Rejected: the first run can miss them with no path to close.
- Baselines only. Rejected: a bless can hide a regression.

## Consequences

- The harness reports tool-surface quality, not agent quality. Reports say so.
- The harness decides open questions: the text block form, the list shape, a query language and the `batch_run` decision rule (ADR-0014).

## Amendment 2026-10-17

- Frozen questions, held-out intents, floors with baselines, the bless log, the provenance lint, the hint-follower robot, abstain and restart scenarios and three-process determinism are new. Confidence calibration moved to stretch S24.

## Amendment 2026-10-17 (revision 3)

- New categories: `decompile` (3), `similar` (2) and `pe` (5). At least 44 scenarios in total.
- WP-30 builds the PE fixtures, so WP-06 cannot write the `pe` questions. WP-30 writes them from the PE truth files (C sources, `.def` files, link maps) with no tool names in the question texts. It appends them to `eval/questions.jsonl` in its register commit and writes the new `questions_sha256` into `eval/thresholds.json`. This is the only change to the questions after WP-06, and it comes before WP-26 starts. Floors do not change.
