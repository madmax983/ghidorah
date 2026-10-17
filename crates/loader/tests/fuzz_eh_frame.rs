//! Fuzz target `eh_frame` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race. The seeds are the
//! `.eh_frame` bytes of T1 fixtures and of `ElfBuilder` files, plus hand-made records.
//! Each case runs in a 256 KiB stack and checks the invariants of the FDE list.

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::path::PathBuf;

use ghidorah_base::Limits;
use ghidorah_loader::ehframe::{EhFrame, Place, parse_bytes};
use ghidorah_loader::{LoadOpts, load};
use ghidorah_testkit::elf::{ElfBuilder, Fde, Loc, Section, Symbol, malformed_variants};
use ghidorah_testkit::fuzz::{self, Config, Outcome};

/// Stage 0: any input. 1: the first record fits. 2: an FDE. 3: an FDE with CFA rows.
const STAGES: [&str; 4] = ["input", "record", "fde", "rows"];

/// The seed fixtures of `fixtures/bin`.
const SEED_FIXTURES: [&str; 4] = [
    "hello.gcc-O2",
    "loops.clang-O2",
    "switch.gcc-O0",
    "syscall_only.gcc-O2",
];

/// The place of every case.
const PLACE: Place = Place {
    va: 0x2000,
    file_off: 0x1000,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn regress_dir() -> PathBuf {
    root().join("tests/regress/eh_frame")
}

/// The `.eh_frame` bytes of an ELF file.
fn eh_frame_of(bytes: &[u8]) -> Option<Vec<u8>> {
    let (b, _) = load(bytes, &LoadOpts::AUTO, &Limits::DEFAULT).ok()?;
    let s = b
        .sections
        .iter()
        .find(|s| s.name.as_bytes() == b".eh_frame")?;
    let start = usize::try_from(s.file_off).ok()?;
    let end = start.checked_add(usize::try_from(s.size).ok()?)?;
    bytes.get(start..end).map(<[u8]>::to_vec)
}

fn seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = SEED_FIXTURES
        .iter()
        .filter_map(|n| {
            let path = root().join("fixtures/bin").join(n);
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            eh_frame_of(&bytes)
        })
        .collect();
    let built = ElfBuilder::exec()
        .section(Section::code(".text", &[0xc3; 64]))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 32))
        .symbol(Symbol::func("g", Loc::section(".text", 32), 32))
        .fde(Fde::frame_pointer(Loc::symbol("f"), 32))
        .fde(Fde {
            at: Loc::symbol("g"),
            len: 32,
            program: vec![
                0x41, 0x0e, 0x10, 0x0a, 0x41, 0x0e, 0x20, 0x41, 0x0b, 0x12, 0x07, 0x7e,
            ],
        })
        .build();
    out.extend(eh_frame_of(&built));
    out.extend(
        malformed_variants()
            .iter()
            .filter_map(|v| eh_frame_of(&v.bytes)),
    );
    // A CIE with zPLR and version 3, and an FDE with the 8-byte length form.
    let mut hand = vec![0x1c, 0, 0, 0, 0, 0, 0, 0, 3];
    hand.extend_from_slice(b"zPLR\0");
    hand.extend_from_slice(&[1, 0x78, 0x10, 7, 0x9b, 0x10, 0, 0, 0, 0x1b, 0x1b]);
    hand.extend_from_slice(&[0x0c, 0x07, 0x08, 0, 0, 0, 0]);
    hand.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x1e, 0, 0, 0, 0, 0, 0, 0]);
    hand.extend_from_slice(&[0x2c, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0x20, 0, 0, 0]);
    hand.extend_from_slice(&[4, 0, 0, 0, 0, 0x41, 0x0e, 0x10, 0x2e, 0x08, 0, 0, 0, 0]);
    out.push(hand);
    out
}

/// Checks the invariants of one walk.
fn check(eh: &EhFrame) -> Result<(), String> {
    for f in &eh.fdes {
        if f.range.first > f.range.last {
            return Err(format!("empty range {:?}", f.range));
        }
        let mut last = None;
        for r in &f.cfa_rows {
            if !f.range.contains(r.pc) {
                return Err(format!("row {r:?} outside {:?}", f.range));
            }
            if last.is_some_and(|l| l >= r.pc) {
                return Err(format!("rows out of order at {:#x}", r.pc));
            }
            last = Some(r.pc);
        }
    }
    if eh.diagnostics.len() > ghidorah_loader::diag::MAX_DIAGNOSTICS {
        return Err("too many diagnostics".to_string());
    }
    Ok(())
}

fn target(input: &[u8]) -> Outcome {
    let first = parse_bytes(input, PLACE, &Limits::DEFAULT);
    if parse_bytes(input, PLACE, &Limits::DEFAULT) != first {
        return Outcome::violation(1, "two walks differ".to_string());
    }
    if let Err(message) = check(&first) {
        return Outcome::violation(1, message);
    }
    let fits = input
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .is_some_and(|len| len != 0 && u64::from(len) + 4 <= input.len() as u64);
    let stage = if first.fdes.iter().any(|f| !f.cfa_rows.is_empty()) {
        3
    } else if !first.fdes.is_empty() {
        2
    } else if fits {
        1
    } else {
        0
    };
    Outcome::reached(stage)
}

#[test]
fn fuzz_eh_frame() {
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new("eh_frame", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 64 << 10;
    let seeds = seeds();
    assert!(seeds.len() >= 8, "{} seeds", seeds.len());
    let report = fuzz::run(&config, &seeds, target)
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
