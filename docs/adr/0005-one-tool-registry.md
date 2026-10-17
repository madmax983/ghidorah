# ADR-0005: One tool registry for all surfaces

Status: Accepted (amended 2026-10-17, revision 3)
Date: 2026-10-16
Verified by: AC-129a to AC-129f, AC-130a to AC-130c, AC-131a to AC-131c, AC-132a, AC-132b, AC-149a, AC-149b, AC-222

## Context

- Agents reach ghidorah through MCP, the CLI, JSONL scripts and `batch_run`. Separate surfaces drift, and a fix lands in only one of them (research 3.2).
- Hosts limit tool counts and cut descriptions at 4,096 characters. Tool search cut upfront context from about 77K to 8.7K tokens (research 3.2).
- GhidraMCP shows tool sprawl, for example `rename_function` next to `rename_function_by_address`.
- Parallel WPs that edit one central table conflict.

## Decision

- One registry of `ToolSpec` and `ArgSpec` items in `ghidorah-tools` is the single source. Its outputs: the JSON Schema subset, the argument parser, lenient coercion, CLI help, MCP `tools/list`, `ghidorah tools --json`, `tool_search`, the server instructions, the schema fuzzer, the eval lints and the registry lint. Handlers are `fn` pointers.
- Registration per item: each handler file exports `pub const SPEC: ToolSpec`. `registry.rs` is a plain list. A WP appends to it in one register commit.
- The full profile has 23 merged `resource_verb` tools in a fixed order (design Section 10.3). Every target argument takes the shared address grammar, so there are no `by_name` and `by_address` twins.
- One vocabulary: `target`, `targets`, `at`, `in`, `max_steps`, `max_chars`. A registry lint enforces it. Aliases live only in each `ArgSpec`.
- Selector tools list their actions with one description line, one example and the required and forbidden arguments of each action.
- `OutputShape` is a typed tree per tool. Examples must fit it, and `batch_run` types references with it. No tool declares `outputSchema` (ADR-0006).
- Profiles are registry data: `full`, `readonly` and `mini` (10 tools). `--tools` adds an allowlist.
- `tool_search` returns names, summaries or full schemas, and serves concept topics.
- Every registry example runs as a test and matches a golden file.

## Alternatives

- Separate CLI and MCP definitions. Rejected: they drift.
- `dyn` tool objects. Rejected: no const data for schemas, docs and lints.
- About 100 explicit tools (GhidrAssistMCP v3). Rejected: catalog cost and selection errors. Selector tools get per-action lines and examples instead.
- One code-mode tool (Hex-Rays). Rejected: a second language surface (ADR-0014).

## Consequences

- One matrix of tests proves budget, envelope, error, coercion and schema rules for every tool.
- The catalog-size gates (24,000 characters for `full`, 6,000 for `mini`) limit description growth.
- A new tool means one handler file with its `SPEC` and examples. A tool count above 25 needs an ADR.

## Amendment 2026-10-17

- The catalog has 22 tools: `patch_apply` (S26) and `emu_run` (S8) moved to the stretch list. The `lazy` profile (S21) and the legacy alias table (S15) moved to the stretch list.
- Registration per item, the vocabulary lint, actions, `OutputShape` and `dispatch_with` are new.

## Amendment 2026-10-17 (revision 3)

- Tool 23 `func_similar` (ADR-0028) joins the `full` and `readonly` profiles. `mini` keeps its 10 tools.
- `func_get` has the `decomp` section and IR level `l1` in the MVP.
- `binary_load` accepts `format: "pe"` (ADR-0029).
