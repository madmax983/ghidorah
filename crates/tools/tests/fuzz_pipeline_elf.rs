//! Fuzz target `pipeline_elf` (design Section 13.5, AC-190a, AC-190c and AC-190d).
//!
//! This binary has one test, so the global panic hook has no race. Each case applies havoc to a
//! T1 fixture or an `ElfBuilder` file. Then it runs the tool pipeline: `binary_load`,
//! `analysis_run` with a fuel cap, `func_list` and `func_get` with every section for every
//! function. A result with `INTERNAL_ERROR` is a violation. Each case reports the deepest ELF
//! stage of its input, and each stage needs at least 10% of the cases.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

#[path = "pipeline/mod.rs"]
mod pipeline;

use std::path::Path;

use ghidorah_testkit::fuzz::{self, Config, Outcome};

use crate::pipeline::{ELF_STAGES, Load, elf_seeds, elf_stage, regress_dir, run, work_dir};

/// The target name.
const TARGET: &str = "pipeline_elf";

/// The number of cases of one tier-1 run.
const CASES: u32 = 2_000;

fn target(dir: &Path, input: &[u8]) -> Outcome {
    let stage = elf_stage(input);
    match run(dir, input, Load::Auto) {
        Ok(_) => Outcome::reached(stage),
        Err(message) => Outcome::violation(stage, message),
    }
}

#[test]
fn fuzz_pipeline_elf() {
    let dir = work_dir(TARGET);
    let replay = fuzz::replay_regress(&regress_dir(TARGET), |input| target(&dir, input))
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new(TARGET, CASES);
    config.stages = ELF_STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir(TARGET));
    config.max_len = 64 << 10;
    let report = fuzz::run(&config, &elf_seeds(), |input| target(&dir, input))
        .unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, CASES);
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
    for (stage, name) in ELF_STAGES.iter().enumerate().skip(1) {
        assert!(
            report.reached_percent(stage) >= 10,
            "stage {name}: {:?}",
            report.reached
        );
    }
}
