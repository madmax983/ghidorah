//! The start call of `MainDiscovery` over the published facts (design Section 7.11).

use ghidorah_analysis::main_discovery;
use ghidorah_base::Fuel;
use ghidorah_loader::EntryKind;

use crate::support::{cached, fir_of, fixtures, truth, truth_funcs};

#[test]
fn main_from_the_start_call() {
    let mut found = 0;
    for f in fixtures() {
        let t = truth(&f.truth);
        let Some(&main) = truth_funcs(&t).get("main") else {
            continue;
        };
        let p = cached(&f.path);
        let entry = p
            .binary()
            .entry_points
            .iter()
            .find(|e| e.kind == EntryKind::Entry)
            .expect("an ELF entry")
            .addr;
        let ir = fir_of(p, entry);
        let call = main_discovery::find(p, &ir, &mut Fuel::new(100_000))
            .unwrap_or_else(|| panic!("{}: a start call", f.path));
        assert_eq!(call.main, main, "{}", f.path);
        assert!(ir.units.contains_key(&call.site));
        found += 1;
    }
    assert!(found > 100, "the fixtures have main: {found}");
    // A program with no C library has no start call.
    let p = cached("fixtures/bin/syscall_only.gcc-O2");
    let entry = p.binary().entry_points[0].addr;
    let ir = fir_of(p, entry);
    assert_eq!(main_discovery::find(p, &ir, &mut Fuel::new(100_000)), None);
}
