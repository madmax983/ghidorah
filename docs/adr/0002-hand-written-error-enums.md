# ADR-0002: Hand-written error enums instead of thiserror and anyhow

Status: Accepted (amended 2026-10-17)
Date: 2026-10-16
Verified by: AC-026, AC-141a, AC-141b, AC-142

## Context

- `thiserror` and `anyhow` are third-party crates. ADR-0001 forbids them.
- Agents need stable codes, not text. Research 3.9 asks for two error tiers and UPPER_SNAKE codes.
- The owner standard bans `unwrap()` in production code.
- Revision 1 used warning codes and C parser codes outside any catalog.

## Decision

- Each crate has its own error enum with a manual `Display`, `std::error::Error` and a `fn code(&self) -> ErrorCode`.
- `ghidorah-base` holds three frozen catalogs, each `#[repr(u16)]`: `ErrorCode` (tool errors), `WarningCode` (result warnings) and `DiagCode` (loader and C parser diagnostics). Each code has a message template, a hint template, a retry flag and a repair class (design Section 10.8).
- Code numbers never change. A frozen-list test guards them, reserved numbers included. A test generates `docs/errors.md` from the three enums.
- C parser codes (`E_SYNTAX` and others) are `DiagCode` values inside `C_PARSE_ERROR.details.errors[]`.
- Lower-level errors (`LoadError`, `DecodeError`, `JsonError`, `CParseError`, `EditError`) carry structured fields (offset, path, need, have) and convert into a tool error at the dispatcher.
- `From` impls convert between crate errors. No `Box<dyn Error>` crosses a crate API.
- Clippy denies `unwrap_used`, `expect_used`, `panic`, `todo` and `unimplemented` outside tests.

## Alternatives

- `thiserror` and `anyhow`. Rejected by ADR-0001.
- `Box<dyn Error>` across crate APIs. Rejected: it loses the stable code.
- String errors. Rejected: agents and tests cannot match them.

## Consequences

- About 60-100 lines per crate for error types. The budget includes them.
- Every error path has a stable code that tests and agents can match.
- Error text never contains Rust debug output (AC-142).

## Amendment 2026-10-17

- `WarningCode` and `DiagCode` became frozen catalogs. C parser codes moved into `C_PARSE_ERROR.details`. Numbers 24, 25 and 39 are reserved for stretch items.
