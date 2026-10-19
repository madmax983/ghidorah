# License ledger

This ledger lists each vendored data file of the repository with its source and its license.
The repository code uses the Apache-2.0 license (`LICENSE`). The build uses no third-party crate.

Rules:

- Add one row for each vendored data file in the same commit as the file.
- Put a license header in each data file that names its source and its license.
- Add the same file to `NOTICE`.
- Never check in a GPL or LGPL binary (ADR-0020).

| File | Source | License | Added by |
|---|---|---|---|
| `tests/data/jsontestsuite/*.json` (318 files, license text in `tests/data/jsontestsuite/LICENSE`) | JSONTestSuite, `test_parsing` at commit `1ef36fa0` (<https://github.com/nst/JSONTestSuite>) | MIT | WP-04 |
| `crates/types/data/noreturn_elf.txt` (21 names) | Ghidra, `Ghidra/Features/Base/data/ElfFunctionsThatDoNotReturn` (<https://github.com/NationalSecurityAgency/ghidra>) | Apache-2.0 | WP-10 |
| `crates/types/data/noreturn_pe.txt` (21 names) | Ghidra, `Ghidra/Features/Base/data/PEFunctionsThatDoNotReturn` (<https://github.com/NationalSecurityAgency/ghidra>) | Apache-2.0 | WP-30 |
| `crates/types/data/syscalls_x86_64.txt` (373 entries) | Linux 6.8 uapi `asm/unistd_64.h`, the `__NR_` names and numbers recorded as interface facts, no header text | Apache-2.0 (part of ghidorah) | WP-10 |
