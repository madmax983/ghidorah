# ADR-0024: Closed-world analyzers, extension seams and no prologue gap fill

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-077, AC-078, AC-093, AC-210

## Context

- A `dyn` plugin system adds a nondeterministic order and hidden behavior. Ghidra uses Java plugins that agents cannot inspect.
- Prologue matching has 77.53% mean precision and added 4,128 false positives in FETCH. `endbr64` heads plus call and tail-call targets cover 99.99% of CET functions (research 3.6).
- One central analyzer table makes parallel WPs conflict.

## Decision

- `AnalyzerId` is a closed enum. Each analyzer file exports `pub const SPEC: AnalyzerSpec` (name, Ghidra priority band, triggers, version, options) and a `run` function. `analysis/src/registry.rs` is a plain list. Dispatch is one `match`.
- Only analyzers at band 800 or above list the `Signatures` trigger. So a signature edit re-runs only those bands (ADR-0004).
- Knowledge lives in versioned data files embedded with `include_str!` (noreturn names, Tier-0 prototypes, syscall numbers, calling conventions), each with a license header.
- New formats, ISAs and analyzers are new enum variants or new crates. ISA crates depend on `ir`, never the reverse.
- External automation uses `ghidorah jsonl` and `batch_run` with its own session label. The agent is the plugin.
- No prologue-pattern gap fill in the MVP. Unclaimed executable ranges become gap items in the worklist with a `func_edit create` remedy.

## Alternatives

- A `dyn` plugin API. Rejected: hidden order and behavior.
- Prologue-pattern gap fill. Rejected: low precision (research 3.6).
- An embedded script engine. Rejected by ADR-0014.

## Consequences

- Analyzer order is fixed and visible in `analysis_run` output.
- Discovery without `.eh_frame` relies on calls, tail calls and `endbr64`. The 0.90 F1 gate on no-`.eh_frame` variants measures the effect. If it fails, a Nucleus-style component pass is the next step.

## Amendment 2026-10-17

- Registration per file and the `Signatures` band rule are new.
