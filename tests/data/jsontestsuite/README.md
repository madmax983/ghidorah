# JSONTestSuite parsing files

This directory holds the `test_parsing` files of JSONTestSuite.

- Source: <https://github.com/nst/JSONTestSuite>, commit `1ef36fa01286573e846ac449e8683f8833c5b26a`, directory `test_parsing`.
- License: MIT. The file `LICENSE` holds the license text (Copyright (c) 2016 Nicolas Seriot).
- Use: the test `ac_039_json_test_suite` of `ghidorah-json` (AC-039) and the seeds of the fuzz target `json_parse`.

Rules:

- Do not edit the `.json` files. Some files hold bytes that are not UTF-8 on purpose.
- A `y_` file must parse. An `n_` file must fail. `crates/json/tests/data/i_pinned.txt` holds the result of each `i_` file.
- The `.gitattributes` file keeps git from a change of the line ends.
