# ADR-0029: PE32+ in the MVP

Status: Accepted
Date: 2026-10-17
Verified by: AC-244 to AC-255

## Context

- Revision 2 deferred the PE/COFF loader (about 2,000 lines) as the first breadth item after the MVP.
- Agents often meet Windows binaries. The owner moved the PE32+ x86-64 loader into the MVP in revision 3.
- The x86-64 decoder, lifter, analysis and decompiler do not depend on the format. A PE loader reuses them. Only the calling convention, the data model and some seeds change.
- Research 3.3 measured that lld-link makes PE32+ fixtures offline with imports, delay imports, forwarders, TLS, DIR64 relocations and `.pdata`. The pinned toolchain ships `rust-lld`, `llvm-readobj` and `llvm-objdump`. The fixture recipe with `clang --target=x86_64-pc-windows-msvc` and `/nodefaultlib` was measured on the build host.
- Hostile PE files have known traps: relocation blocks that never advance, huge export counts, overlapping sections, sections past EOF and cyclic chains (research 3.3).

## Decision

- WP-30 adds a `pe` module to `ghidorah-loader` for PE32+ files with `Machine = 0x8664` (EXE and DLL): headers, data directories, loader-faithful RVA mapping, imports with ordinals and hints, delay imports, exports with forwarders, base relocations, TLS callbacks, `.pdata`, the CodeView identity and protections (design Sections 4.9 to 4.15).
- PE32 files and PE32+ files for other machines give `UNSUPPORTED_FORMAT` with the detected kind. They need i386 mode or other ISAs, which stay deferred.
- Import IDs are `imp:<dll>!<name>` and `imp:<dll>!#<ordinal>` (ADR-0008). IAT slots get `__imp_<name>` symbols. `jmp [rip+IAT]` thunks and `call [rip+IAT]` sites resolve to the import.
- Analysis: `.pdata` starts seed functions (start reason `pdata`, CHAININFO fragments skipped). TLS callbacks and exports into code are entry points. PE functions use the MS x64 calling convention from `types`. PE records use the natural layout with LLP64 sizes (`x86_64-win`). Bit-fields stay deferred.
- Fixtures build offline with `clang --target=x86_64-pc-windows-msvc -O2 -c` and `rust-lld -flavor link` with `/nodefaultlib`. Goldens come from `llvm-readobj` and `llvm-objdump`. `PeBuilder` in `ghidorah-testkit` makes malformed variants. The `pe_load` fuzz target runs 10,000 fixed-seed cases.
- WP-30 appends a `pe` question group to the frozen eval questions once (ADR-0015).
- Mach-O, ELF32, big-endian ELF, AArch64 and RISC-V stay deferred.

## Alternatives

- Keep PE deferred. Rejected by the owner in revision 3.
- PE32 and PE32+ together. Rejected: PE32 needs i386 mode and 32-bit forms that no MVP AC uses.
- A survey-only load for other machines, as for ELF. Rejected: other machines need their own `.pdata` forms, fixtures and goldens, and no MVP AC uses them.
- Strict mapping as in the `object` crate. Rejected: hostile files then give wrong or missing data (research 3.3).
- Thunk detection in the loader by a byte scan. Rejected: the same bytes can be a tail call inside a function. Analysis marks thunks after disassembly.

## Consequences

- The same agent workflow works on ELF and PE binaries, pseudo-C included.
- The loader grows by about 1,450 lines. The line plan records it as information only (ADR-0018).
- The PE parser gets the same never-panic fuzzing as the ELF parser.
- clang and lld output can differ from MSVC output. `PeBuilder` variants cover the MSVC forms that the fixtures lack, for example CHAININFO chains.
