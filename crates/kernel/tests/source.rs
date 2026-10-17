//! K7 tier-1 test: the provenance write rule against the table of design Section 3.6 (AC-033).

use ghidorah_kernel::may_overwrite;
use ghidorah_kernel::source::{AGENT, ANALYSIS, DEFAULT, IMPORTED, USER};

/// `ALLOWED[force][old - 1][new - 1]`: the write rule of design Section 3.6.
const ALLOWED: [[[bool; 5]; 5]; 2] = [
    // force = false
    [
        [true, true, true, true, true],
        [false, true, true, true, true],
        [false, false, true, true, true],
        [false, false, false, true, true],
        [false, false, false, false, true],
    ],
    // force = true: an Agent write (3) over an Imported fact (4) succeeds.
    [
        [true, true, true, true, true],
        [false, true, true, true, true],
        [false, false, true, true, true],
        [false, false, true, true, true],
        [false, false, false, false, true],
    ],
];

#[test]
fn ac_033_source_table_exhaustive() {
    assert_eq!([DEFAULT, ANALYSIS, AGENT, IMPORTED, USER], [1, 2, 3, 4, 5]);
    let mut cases = 0;
    for (f, table) in ALLOWED.iter().enumerate() {
        for (o, row) in table.iter().enumerate() {
            for (n, &want) in row.iter().enumerate() {
                let (old, new, force) = (o as u8 + 1, n as u8 + 1, f == 1);
                assert_eq!(
                    may_overwrite(old, new, force),
                    want,
                    "may_overwrite({old}, {new}, {force})"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 50);
}
