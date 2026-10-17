# ADR-0007: Hex-string addresses, address input grammar and range representation

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-046a, AC-046b, AC-137, AC-138, AC-215

## Context

- Values above 2^53 lose precision as JSON numbers in JavaScript and Python (measured with `0xffffffff81000123`).
- Models often write hex without `0x`. A digits-only string can be valid in both bases and map in a small PIE, which causes wrong edits with no error.
- Binary Ninja reads an address input as an expression and requires a prefix for decimal (research 3.2).
- A range that ends at `0xffff_ffff_ffff_ffff` has no exclusive end.
- Real ELF names collide with an unordered grammar: `puts@GLIBC_2.2.5`, `x@plt`, a real `FUN_00401000`, `foo.cold`.

## Decision

- Output writes every 64-bit value as a lowercase `0x` hex string. JSON numbers in output stay below 2^53.
- Input resolution order (the first rule that matches wins): JSON integer, `0x` hex, registered ID prefix (`sym:<name>` skips every other rule), exact symbol name of the whole string, section name, computed default name (only when no real symbol has that name), `name@0x<hex>`, then `term+0x..` or `term-0x..` split at the last sign (design Section 10.5).
- The resolver returns `resolved_from: { rule, matched }`.
- One target-resolution table maps each ID kind to the addresses of each tool family. For example, `imp:X` in `xref_list` covers stub, GOT and direct call sites.
- A string of digits only gives `ADDRESS_BASE_AMBIGUOUS` with both readings and their mapped state. The server never guesses. Offsets in expressions must also use `0x`.
- Ambiguous names give `AMBIGUOUS_NAME` with all candidates. The resolver never picks a match.
- Internal ranges are inclusive `[first, last]` and use the kernel K2 math. Agent-facing ranges are `{start, size}`. Input also accepts `{start, end}` with an exclusive end.
- A `calc` tool does base conversion and address arithmetic.

## Alternatives

- Decimal as the default reading of digits. Rejected: wrong edits with no error.
- A `0n` prefix for decimal (Binary Ninja). Rejected: JSON integers already carry decimal values.
- First match on an ambiguous name. Rejected: research 3.2 pitfall.
- An unordered grammar. Rejected: real names collide with its forms.

## Consequences

- Agents never do hex arithmetic in their heads, and output keeps full precision.
- The K3 RangeSet proof must be redone for inclusive ranges. The time box covers it.
- The repair robot treats `ADDRESS_BASE_AMBIGUOUS` and `AMBIGUOUS_NAME` as choice codes.

## Amendment 2026-10-17

- The rule order, the `sym:` escape, `resolved_from` and the target-resolution table are new.
