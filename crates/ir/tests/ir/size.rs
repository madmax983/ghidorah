//! AC-067: the size budgets of `Op`, `Insn` and `Address`.

use ghidorah_base::Address;
use ghidorah_ir::{Arg, Loc, Op, Val};

/// The x86 test binary that holds the `Insn` size test.
const INSN_TEST: &str = "../x86/tests/x86/model.rs";

#[test]
fn ac_067_size_budgets() {
    assert!(size_of::<Op>() <= 64, "Op has {} bytes", size_of::<Op>());
    assert_eq!(size_of::<Address>(), 16);
    assert!(size_of::<Arg>() <= 12, "Arg has {} bytes", size_of::<Arg>());
    assert_eq!(size_of::<Val>(), 4);
    assert!(size_of::<Loc>() <= 8);
    // The ir crate cannot depend on ghidorah-x86 (design Section 2.2). The x86 test binary
    // holds the `Insn` check, and this test makes sure that the check stays there.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(INSN_TEST);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        text.contains("fn insn_fits_64_bytes()") && text.contains("size_of::<Insn>() <= 64"),
        "{} holds the Insn size test",
        path.display()
    );
}
