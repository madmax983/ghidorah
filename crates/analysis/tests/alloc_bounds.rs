//! Allocation bounds of the scaling paths of the analysis.
//!
//! This binary installs the counting allocator of `ghidorah-oracle`. Each test counts the
//! bytes that one path allocates for an input of size `n` and of size `2 n`. The count of
//! a fixed input is the same on each run, so the tests use no clock. A linear path allocates
//! about twice the bytes for twice the input. A path that copies its state on each step
//! allocates about four times the bytes.

#![allow(clippy::expect_used, reason = "test helpers fail through expect")]

use ghidorah_analysis::analyzers::gaps;
use ghidorah_base::Limits;
use ghidorah_db::Program;
use ghidorah_loader::{LoadOpts, load};
use ghidorah_oracle::alloc::CountingAlloc;
use ghidorah_testkit::elf::{ElfBuilder, Fde, Loc, Section, Symbol};

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc::new();

/// The code of one small frame-pointer function and its padding.
const BODY: [u8; 16] = [
    0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

/// Builds an ELF with `n` small functions. Each function has an FDE. With `symbols`, each
/// function also has a function symbol over its padding.
fn functions(n: u64, symbols: bool) -> Program {
    let text: Vec<u8> = (0..n).flat_map(|_| BODY).collect();
    let mut elf = ElfBuilder::exec()
        .section(Section::code(".text", &text))
        .entry(Loc::section(".text", 0));
    for i in 0..n {
        elf = elf.fde(Fde::frame_pointer(Loc::section(".text", i * 16), 6));
        if symbols {
            let at = Loc::section(".text", i * 16 + 8);
            elf = elf.symbol(Symbol::func(&format!("f{i}"), at, 2));
        }
    }
    let (binary, mem) = load(&elf.build(), &LoadOpts::AUTO, &Limits::DEFAULT).expect("a load");
    Program::from_binary(binary, mem, &Limits::DEFAULT).expect("a program")
}

/// Asserts that twice the input allocates at most 2.5 times the bytes.
fn assert_linear(what: &str, small: u64, large: u64) {
    assert!(
        large * 2 <= small * 5,
        "{what}: twice the input allocates {large} bytes, not about 2 x {small}"
    );
}

/// The owned set of the gaps goes in by start. Each function symbol went in after all FDEs,
/// in the middle of the set, and copied the tail of the set.
#[test]
fn regress_gap_sets_allocate_linearly() {
    let bytes = |n: u64| {
        let program = functions(n, true);
        let (items, stats) = ALLOC.measure(|| gaps::items(&program));
        assert!(items.len() < 2, "the FDEs and symbols own the code");
        stats.allocated_bytes
    };
    assert_linear("gaps::items", bytes(10_000), bytes(20_000));
}
