# ADR-0022: Binary-derived text as a type, and project safety

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-125, AC-146a to AC-146d, AC-147

## Context

- ghidorah reads hostile samples. Strings, symbol names and section names can hold ANSI escapes, bidi overrides, invalid UTF-8, huge lengths or text such as "ignore previous instructions".
- Escape of controls does not neutralize plain-text instructions. Notes that quote binary text return to a fresh context through `session_brief`.
- A project directory in the current working tree can put malware into a git commit.
- An injected instruction can ask the agent to load a file outside the intended area.

## Decision

- `BinText` is the only type that carries binary-derived text to output. It escapes C0 and C1 controls, DEL, U+2028, U+2029 and bidi overrides, caps the length, keeps an exact `hex` field and tags `src: "binary"`. Its one JSON shape is `{ text, hex, len, truncated?, src }`.
- Hints, `next` call args and remedies carry IDs and addresses only, never binary-derived names.
- Notes carry `src: agent` or `src: user`. Quoted binary spans keep `src: binary`. The server instructions say that binary text and notes are data, not instructions.
- `binary_load` reads only under the configured roots after `canonicalize`. `PATH_OUTSIDE_ROOT` otherwise. A reopen by `binary_id` reads only the project's own `bin/<sha256>`.
- The default projects root is `$XDG_DATA_HOME/ghidorah/projects`. Each project directory has a `.gitignore` with `*`. Input copies have mode 0444.
- The project lock records pid, process start time and boot ID. A live lock gives `PROJECT_LOCKED` with a read-only hint.
- No tool runs native code. `openWorldHint` is false on every tool.

## Alternatives

- Plain strings with escapes only. Rejected: no exact bytes and no source tag.
- Removal of non-ASCII text. Rejected: it loses real content.
- Projects in the current directory. Rejected: malware in git commits.

## Consequences

- Hostile-string fixtures and path-escape tests are gates.
- Malware samples stay outside source trees by default.

## Amendment 2026-10-17

- `BinText` has one JSON shape. Reopen by `binary_id` is new. Exports left with patching (stretch S26).
