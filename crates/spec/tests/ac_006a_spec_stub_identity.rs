//! AC-006a: `ghidorah-spec` has no dependencies, and annotated items behave as unannotated copies.

use std::cell::Cell;

use ghidorah_spec::{proof, verus_spec, verus_verify};

/// An annotated struct with an annotated impl.
#[verus_verify]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pair {
    a: u32,
    b: u32,
}

#[verus_verify]
impl Pair {
    #[verus_spec(r => ensures r == self.a + self.b)]
    const fn sum(self) -> u32 {
        self.a.wrapping_add(self.b)
    }
}

/// The unannotated copy of [`Pair`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlainPair {
    a: u32,
    b: u32,
}

impl PlainPair {
    const fn sum(self) -> u32 {
        self.a.wrapping_add(self.b)
    }
}

/// An annotated enum.
#[verus_verify]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Left,
    Right,
}

#[verus_verify]
const LIMIT: u32 = 7;

#[verus_spec(r =>
    requires
        x < 100,
    ensures
        r == x * 2 + 1,
)]
fn odd(x: u32, _ghost_steps: &Cell<u32>) -> u32 {
    proof! {
        _ghost_steps.set(_ghost_steps.get() + 1);
    }
    x * 2 + 1
}

fn plain_odd(x: u32) -> u32 {
    x * 2 + 1
}

#[verus_spec(r => ensures r <= LIMIT)]
fn count_to_limit(_ghost_steps: &Cell<u32>) -> u32 {
    let mut i = 0;
    #[cfg_attr(verus_only, verus_spec(invariant i <= LIMIT, decreases LIMIT - i))]
    while i < LIMIT {
        proof! { _ghost_steps.set(_ghost_steps.get() + 1); }
        i += 1;
    }
    i
}

/// Checks that the `ghidorah-spec` manifest has no dependency table of any kind.
fn assert_no_dependencies() {
    let manifest = include_str!("../Cargo.toml");
    let tables: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('['))
        .collect();
    assert_eq!(
        tables,
        ["[package]", "[lib]", "[lints]"],
        "ghidorah-spec takes no dependency of any kind"
    );
    assert!(manifest.contains("proc-macro = true"));
    for line in manifest.lines().map(str::trim) {
        assert!(
            !line.contains("dependencies") && !line.starts_with("[target"),
            "ghidorah-spec takes no dependency: {line}"
        );
    }
}

#[test]
fn ac_006a_spec_stub_identity() {
    assert_no_dependencies();

    let steps = Cell::new(0);
    for x in [0, 1, 7, 99] {
        assert_eq!(odd(x, &steps), plain_odd(x));
    }
    assert_eq!(steps.get(), 0, "proof! must expand to nothing");

    assert_eq!(count_to_limit(&steps), LIMIT);
    assert_eq!(steps.get(), 0, "proof! in a loop must expand to nothing");

    for (a, b) in [(0, 0), (1, 2), (u32::MAX, 1)] {
        assert_eq!(Pair { a, b }.sum(), PlainPair { a, b }.sum());
    }
    assert_eq!(Side::Left, Side::Left);
    assert_ne!(Side::Left, Side::Right);
    assert_eq!(size_of::<Pair>(), size_of::<PlainPair>());
}
