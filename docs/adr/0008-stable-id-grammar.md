# ADR-0008: Stable ID grammar

Status: Accepted (amended 2026-10-17, revision 3)
Date: 2026-10-16
Verified by: AC-045

## Context

- Agents cite evidence across calls, sessions and context resets. A name is not a stable key.
- The planning inputs used different forms (`f@401130/v/stack:-0x14` and `var:0x401130/stack:-0x14`; `imp:libc!puts` and `imp:libc.so.6!puts`). A late change breaks journals and goldens.
- ELF imports do not bind a library without symbol-version mapping, which is deferred.
- Some symbol names collide with other input forms (ADR-0007).

## Decision

- The ID kinds and text forms in design Section 3.5 are frozen: `fn:`, `bb:`, `op:<addr>:<seq>`, `var:<entry>/<storage>`, `imp:<name>`, `exp:`, `sym:<exact name>`, `ext:<hex>`, `sys:`, `sec:<index>:<name>`, `seg:`, `str:`, `jt:`, `ref:<from>><to>:<kind>`, `t:<name>` or `t:#<fnv64>`, `note:`, `set:`, `tx:`.
- `binary_id` is the first 16 hex digits of the file SHA-256. Metadata holds the full hash.
- Function IDs are entry addresses. Variable IDs are storage-based. A rename never changes an ID.
- `imp:<lib>!<name>` is for formats that bind a library. PE uses `imp:<dll>!<name>` and `imp:<dll>!#<ordinal>` with the DLL name in ASCII lowercase, and the parser splits at the first `!`. A PE export without a name is `exp:#<ordinal>`. Mach-O keeps the form reserved.
- OpIds carry `lift_ver` in metadata. A read with another `lift_ver` reports `W_STALE_OP_ID`.
- One parser in `ghidorah-base` reads every kind. A property test checks `parse(display(id)) == id`.

## Alternatives

- `f@401130/v/stack:-0x14` forms. Rejected: two separators and no kind prefix.
- `imp:libc.so.6!puts` for ELF. Rejected: ELF does not bind a library to an import.
- Name-based IDs. Rejected: a rename breaks them.

## Consequences

- Persisted agent work anchors on address-level IDs, which survive analyzer upgrades better than OpIds.
- A new ID kind needs an ADR amendment and a new round-trip case.

## Amendment 2026-10-17

- `sym:` (an input escape for exact names) and `ext:` (EXTERNAL addresses as input) are new kinds.

## Amendment 2026-10-17 (revision 3)

- The PE forms of `imp:` and `exp:` are in use (ADR-0029). They are forms of existing kinds, not new kinds, and the round-trip property covers them.
