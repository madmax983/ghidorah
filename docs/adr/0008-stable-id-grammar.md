# ADR-0008: Stable ID grammar

Status: Accepted (amended 2026-10-20)
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
- An index ID such as `imp:#<index>` for a hostile name. Rejected: the index changes when the loader changes, and the ID no longer names the item.
- Names with escapes but no quotes. Rejected: the name `\x1b` and the name with ESC give the same text.

## Consequences

- Persisted agent work anchors on address-level IDs, which survive analyzer upgrades better than OpIds.
- A new ID kind needs an ADR amendment and a new round-trip case.

## Amendment 2026-10-17

- `sym:` (an input escape for exact names) and `ext:` (EXTERNAL addresses as input) are new kinds.

## Amendment 2026-10-17 (revision 3)

- The PE forms of `imp:` and `exp:` are in use (ADR-0029). They are forms of existing kinds, not new kinds, and the round-trip property covers them.

## Amendment 2026-10-20

- A name part can hold a character that `BinText` escapes (ADR-0022), for example ESC, U+202E, a newline or a tag character. The raw ID then carries hostile text to the agent and to a terminal.
- The name parts are the name of `sym:`, `exp:` and `sec:<index>:`, and the DLL name and the name of `imp:`.
- A name part that holds a character that `BinText` escapes, or that starts with `"`, shows in a quoted form. Every other name part keeps its exact text, so the IDs of normal binaries do not change.
- The quoted form is `"`, the name with escapes and a closing `"`. The escapes are `\\` for a backslash and `\"` for a double quote.
- C0 controls, DEL and C1 controls use `\x` and two hex digits, for example `\x1b`. Each other escaped code point uses `\u{<hex>}`, for example `\u{202e}`.
- Examples: `sym:"\x1b[2J"`, `imp:"evil\x1b.dll"!puts`, `imp:kernel32.dll!"a\u{e0049}"` and `sec:3:"\u{200b}"`.
- The parser undoes the escapes. It accepts the quoted form of a name that needs no quotes. A bad escape or text after the closing quote gives `INVALID_ARGUMENT`.
- `MAX_ID_TEXT` grows to hold two quoted names of `MAX_NAME_LEN` bytes. The round-trip property covers hostile names.
