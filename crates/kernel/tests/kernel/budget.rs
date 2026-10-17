//! K6 tier-1 tests: boundaries and a brute-force check on small slices (AC-032).

use ghidorah_kernel::fit_prefix;
use ghidorah_testkit::pbt::{Gen, check};

/// The `u128` cost of the prefix of `k` items.
fn cost(sizes: &[u64], overhead: u64, sep: u64, k: usize) -> u128 {
    if k == 0 {
        return 0;
    }
    let sum: u128 = sizes[..k].iter().map(|&s| u128::from(s)).sum();
    u128::from(overhead) + sum + u128::from(sep) * (k as u128 - 1)
}

/// The brute-force answer: the largest `k` whose prefix fits.
fn brute(sizes: &[u64], overhead: u64, sep: u64, max: u64) -> usize {
    (0..=sizes.len())
        .rev()
        .find(|&k| k == 0 || cost(sizes, overhead, sep, k) <= u128::from(max))
        .unwrap_or(0)
}

#[test]
fn k6_budget_boundaries() {
    assert_eq!(fit_prefix(&[], 0, 0, 0), 0);
    assert_eq!(fit_prefix(&[], 100, 100, 0), 0);
    assert_eq!(fit_prefix(&[5], 5, 0, 10), 1, "an exact fit counts");
    assert_eq!(fit_prefix(&[5], 6, 0, 10), 0);
    assert_eq!(fit_prefix(&[1, 1, 1], 0, 0, 3), 3);
    assert_eq!(fit_prefix(&[1, 1, 1], 0, 1, 3), 2, "the separators count");
    assert_eq!(fit_prefix(&[0, 0, 0], 0, u64::MAX, u64::MAX), 2);
    assert_eq!(fit_prefix(&[u64::MAX, 1], 0, 0, u64::MAX), 1, "no overflow");
    assert_eq!(fit_prefix(&[1, u64::MAX], u64::MAX, 0, u64::MAX), 0);
    assert_eq!(
        fit_prefix(&[2, 1, 1], 0, 0, 1),
        0,
        "the prefix rule keeps the order"
    );
}

fn gen_size(g: &mut Gen) -> u64 {
    match g.draw(6) {
        0 => g.u64(),
        1 => u64::MAX - g.draw(4),
        _ => g.draw(64),
    }
}

#[test]
fn ac_032_budget_fit_brute_force() {
    check("ac_032_budget_fit_brute_force", 20_000, |g: &mut Gen| {
        let sizes = g.vec(12, gen_size);
        let overhead = gen_size(g);
        let sep = if g.bool() { g.draw(4) } else { gen_size(g) };
        let max = if g.bool() { g.draw(400) } else { gen_size(g) };
        let got = fit_prefix(&sizes, overhead, sep, max);
        let want = brute(&sizes, overhead, sep, max);
        if got == want {
            Ok(())
        } else {
            Err(format!(
                "{sizes:?} overhead {overhead} sep {sep} max {max}: {got} != {want}"
            ))
        }
    });
}
