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
