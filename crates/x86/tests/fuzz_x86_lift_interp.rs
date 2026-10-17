//! Fuzz target `x86_lift_interp` (design Section 13.5).
//!
//! Each case decodes a linear sweep of at most 16 instructions from the input, lifts them
//! and runs the L0 interpreter with fuel. The input bytes are a read-only image, and the
//! first bytes give the register values. No case may panic, fail to lift a decoded
//! instruction or stop with `BadIr`.
//!
//! This binary has one test, so the global panic hook has no race.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test helpers stop on bad fixture data")]

use std::path::PathBuf;

use ghidorah_base::Fuel;
use ghidorah_ir::{Builder, Config, FlatImage, Interp, Loc, StopReason};
use ghidorah_testkit::fuzz::{self, Config as FuzzConfig, Outcome};
use ghidorah_x86::lift::{self, LiftKind};
use ghidorah_x86::{Opts, decode, lift as lift_insn};

/// Stage 0: any input. Stage 1: one instruction decodes. Stage 2: the sweep lifts.
/// Stage 3: a template lifts one instruction. Stage 4: the run takes more than one step.
const STAGES: [&str; 5] = ["input", "decoded", "lifted", "template", "ran"];

/// The address of the first instruction.
const BASE: u64 = 0x40_1000;

/// The largest count of instructions of one sweep.
const MAX_INSNS: usize = 16;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The regression directory of the target: `tests/regress/x86_lift_interp/`.
fn regress_dir() -> PathBuf {
    root().join("tests/regress/x86_lift_interp")
}

fn corpus() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for name in ["loops.gcc-O0", "switch.gcc-O2nv", "xor_decode.clang-O2nv"] {
        let bin = std::fs::read(root().join("fixtures/bin").join(name)).expect("a fixture");
        out.extend(bin.chunks(48).skip(90).take(24).map(<[u8]>::to_vec));
    }
    out.push(vec![0x48, 0x01, 0xc8, 0x0f, 0x94, 0xc0, 0xc3]);
    out.push(vec![0xf3, 0xa4, 0x48, 0xf7, 0xf1, 0xe2, 0xfa]);
    out
}

fn reg_value(input: &[u8], n: usize) -> u128 {
    let mut b = [0u8; 8];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = input
            .get((n * 3 + i) % input.len().max(1))
            .copied()
            .unwrap_or_default();
    }
    u128::from(u64::from_le_bytes(b))
}

fn target(input: &[u8]) -> Outcome {
    let mut b = Builder::new();
    let (mut at, mut count, mut template) = (0usize, 0usize, false);
    while count < MAX_INSNS && at < input.len() {
        let addr = BASE + u64::try_from(at).expect("offset");
        let Ok(insn) = decode(&input[at..], addr, &Opts::DEFAULT) else {
            break;
        };
        template |= matches!(lift::kind(&insn), LiftKind::Template(_));
        if let Err(e) = lift_insn(&insn, &mut b) {
            return Outcome::violation(2, format!("{addr:#x}: {e}"));
        }
        at += usize::from(insn.len());
        count += 1;
    }
    if count == 0 {
        return Outcome::reached(0);
    }
    let arena = b.finish();
    let image = FlatImage::new(BASE, input.to_vec(), false);
    let mut interp = Interp::new(&arena, &image, Config::default());
    for n in 0..16u8 {
        interp.set_loc(Loc::Reg(u16::from(n)), reg_value(input, usize::from(n)));
    }
    interp.set_loc(Loc::Flags, reg_value(input, 16) & 0x8d5);
    let stop = interp.run(BASE, &mut Fuel::new(512));
    if stop.reason == StopReason::BadIr {
        return Outcome::violation(2, format!("BadIr at {}", stop.at));
    }
    match (template, stop.steps > 1) {
        (_, true) => Outcome::reached(4),
        (true, false) => Outcome::reached(3),
        (false, false) => Outcome::reached(2),
    }
}

#[test]
fn fuzz_x86_lift_interp() {
    let replay = fuzz::replay_regress(&regress_dir(), target)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = FuzzConfig::new("x86_lift_interp", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 96;
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
        report.reached_percent(3) >= 30,
        "template share: {:?}",
        report.reached
    );
    assert!(
        report.reached_percent(4) >= 20,
        "run share: {:?}",
        report.reached
    );
}
