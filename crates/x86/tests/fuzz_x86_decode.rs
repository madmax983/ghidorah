//! Fuzz target `x86_decode` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race.
//! The seeds are the spec vectors and slices of the fixture `.text` sections.
//! Each case runs in a 256 KiB stack.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test helpers stop on bad fixture data")]

use std::path::PathBuf;

use ghidorah_testkit::fuzz::{self, Config, Outcome};
use ghidorah_x86::{DecodeError, NoSymbols, Opts, decode, length, print};

/// Stage 0: any input. Stage 1: the bytes have a length. Stage 2: the bytes decode.
/// Stage 3: the instruction has a memory operand.
const STAGES: [&str; 4] = ["input", "length", "decoded", "memory"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The regression directory of the target: `tests/regress/x86_decode/`.
fn regress_dir() -> PathBuf {
    root().join("tests/regress/x86_decode")
}

fn hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
        .collect()
}

fn corpus() -> Vec<Vec<u8>> {
    let spec = std::fs::read_to_string(root().join("tests/data/x86_spec.txt")).expect("spec");
    let mut out: Vec<Vec<u8>> = spec
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| l.split('|').next().map(hex))
        .collect();
    let bin = std::fs::read(root().join("fixtures/bin/loops.gcc-O2")).expect("fixture");
    out.extend(bin.chunks(64).skip(64).take(64).map(<[u8]>::to_vec));
    out
}

fn check(input: &[u8], opts: Opts) -> Outcome {
    match decode(input, 0x40_1000, &opts) {
        Ok(insn) => {
            let n = usize::from(insn.len());
            if !(1..=15).contains(&n) || n > input.len() {
                return Outcome::violation(2, format!("length {n}"));
            }
            if decode(&input[..n], 0x40_1000, &opts) != Ok(insn) {
                return Outcome::violation(2, "prefix decode differs".to_owned());
            }
            if print(&insn, &NoSymbols).is_empty() {
                return Outcome::violation(2, "empty text".to_owned());
            }
            if opts == Opts::DEFAULT && length(input) != Ok(insn.len()) {
                return Outcome::violation(2, "length differs".to_owned());
            }
            let _ = (insn.regs_read(), insn.regs_written(), insn.ops().count());
            Outcome::reached(if insn.mem().is_some() { 3 } else { 2 })
        }
        Err(DecodeError::Truncated {
            have,
            need_at_least,
        }) if need_at_least <= have || need_at_least > 15 => {
            Outcome::violation(0, format!("truncated {have} {need_at_least}"))
        }
        Err(DecodeError::Invalid { .. } | DecodeError::Unsupported { .. }) => Outcome::reached(1),
        Err(_) => Outcome::reached(0),
    }
}

fn target(input: &[u8]) -> Outcome {
    let first = check(input, Opts::DEFAULT);
    if first.violation.is_some() {
        return first;
    }
    let other = Opts {
        amd_branch_osz: true,
        strict_vex_legacy_prefix: true,
    };
    let second = check(input, other);
    if second.violation.is_some() {
        return second;
    }
    first
}

#[test]
fn fuzz_x86_decode() {
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new("x86_decode", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 32;
    let report = fuzz::run(&config, &corpus(), target)
        .unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 2000);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report.crashes
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    assert!(
        report.reached_percent(2) >= 30,
        "decoded share: {:?}",
        report.reached
    );
    assert!(
        report.reached_percent(3) >= 5,
        "memory share: {:?}",
        report.reached
    );
}
