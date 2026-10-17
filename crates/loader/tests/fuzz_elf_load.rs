//! Fuzz target `elf_load` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race. The seeds are small
//! T1 fixtures, `ElfBuilder` files and the malformed variants. Each case runs in a
//! 256 KiB stack and checks the invariants of the model and the map.

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::path::PathBuf;

use ghidorah_base::Limits;
use ghidorah_loader::{Binary, LoadOpts, MemoryMap, load};
use ghidorah_testkit::elf::{
    ElfBuilder, HashStyle, ImportKind, Loc, Section, Symbol, malformed_variants,
};
use ghidorah_testkit::fuzz::{self, Config, Outcome};

/// Stage 0: any input. 1: the header parses. 2: a mapped segment. 3: dynamic entries.
/// 4: symbols. 5: relocations.
const STAGES: [&str; 6] = ["input", "header", "phdr", "dynamic", "symbols", "relocs"];

/// The seed fixtures of `fixtures/bin`.
const SEED_FIXTURES: [&str; 6] = [
    "hello.gcc-O2",
    "hello.gcc-O2.noshdr",
    "hello.clang-O2.stripped",
    "syscall_only.gcc-O2",
    "switch.gcc-O2-at400000",
    "socket_client.gcc-O2.noshdr",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn regress_dir() -> PathBuf {
    root().join("tests/regress/elf_load")
}

fn seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = SEED_FIXTURES
        .iter()
        .map(|n| {
            let path = root().join("fixtures/bin").join(n);
            std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        })
        .collect();
    let built = ElfBuilder::dyn_object()
        .section(Section::code(
            ".text",
            &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3],
        ))
        .section(Section::data(".data", &[0u8; 32]))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 6))
        .export(Symbol::func("f", Loc::section(".text", 0), 6))
        .import("puts", ImportKind::Plt)
        .needed("libc.so.6")
        .relr(Loc::section(".data", 8))
        .hash(HashStyle::Both);
    out.push(built.build());
    out.push(built.strip_section_headers().build());
    out.extend(malformed_variants().into_iter().map(|v| v.bytes));
    out
}

/// Checks the invariants of one load.
fn check(binary: &Binary, map: &MemoryMap, len: usize) -> Result<(), String> {
    let mut last: Option<u64> = None;
    for r in map.regions() {
        if r.va.first > r.va.last {
            return Err(format!("empty region {r:?}"));
        }
        if last.is_some_and(|l| l >= r.va.first) {
            return Err(format!("regions overlap at {:#x}", r.va.first));
        }
        last = Some(r.va.last);
        let end = r.file_off.checked_add(r.file_size);
        if end.is_none_or(|e| e > len as u64) {
            return Err(format!("region file part past the file: {r:?}"));
        }
        if u128::from(r.file_size) > r.va.len() {
            return Err(format!("file part larger than the region: {r:?}"));
        }
    }
    if binary.diagnostics.len() > ghidorah_loader::diag::MAX_DIAGNOSTICS {
        return Err("too many diagnostics".to_string());
    }
    Ok(())
}

fn target(input: &[u8]) -> Outcome {
    let first = load(input, &LoadOpts::AUTO, &Limits::DEFAULT);
    let Ok((binary, map)) = first else {
        return Outcome::reached(0);
    };
    let again = load(input, &LoadOpts::AUTO, &Limits::DEFAULT);
    if again.as_ref().ok() != Some(&(binary.clone(), map.clone())) {
        return Outcome::violation(1, "two loads differ".to_string());
    }
    if let Err(message) = check(&binary, &map, input.len()) {
        return Outcome::violation(1, message);
    }
    let stage = if !binary.relocs.is_empty() {
        5
    } else if !binary.symbols.is_empty() {
        4
    } else if !binary.dynamic.is_empty() {
        3
    } else if !map.is_empty() {
        2
    } else {
        1
    };
    Outcome::reached(stage)
}

#[test]
fn fuzz_elf_load() {
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new("elf_load", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 64 << 10;
    let report = fuzz::run(&config, &seeds(), target)
        .unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 2000);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report
            .crashes
            .iter()
            .map(|c| &c.message)
            .collect::<Vec<_>>()
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    for (stage, name) in STAGES.iter().enumerate().skip(1) {
        assert!(
            report.reached_percent(stage) >= 10,
            "stage {name}: {:?}",
            report.reached
        );
    }
}
