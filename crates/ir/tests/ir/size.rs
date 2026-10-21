//! AC-067: the size budgets of `Op`, `Insn` and `Address`.

use ghidorah_base::Address;
use ghidorah_ir::{Arg, Loc, Op, Val};

#[test]
fn ac_067_size_budgets() {
    assert!(size_of::<Op>() <= 64, "Op has {} bytes", size_of::<Op>());
    assert_eq!(size_of::<Address>(), 16);
    assert!(size_of::<Arg>() <= 12, "Arg has {} bytes", size_of::<Arg>());
    assert_eq!(size_of::<Val>(), 4);
    assert!(size_of::<Loc>() <= 8);
    // The ir crate cannot depend on ghidorah-x86 (design Section 2.2).
    // The x86 evidence test `ac_067_insn_fits_64_bytes` holds the `Insn` check.
}
