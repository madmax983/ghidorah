//! Fuzz target `pipeline_raw` (design Section 13.5, AC-190a and AC-190c).
//!
//! This binary has one test, so the global panic hook has no race. Each case loads the input
//! as a raw x86-64 blob at `0x400000`. The first two bytes pick the entry. Then the case runs
//! `analysis_run` with a fuel cap, `func_list` and `func_get` with every section for every
//! function. A result with `INTERNAL_ERROR` is a violation.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

#[path = "pipeline/mod.rs"]
mod pipeline;

use std::path::Path;

use ghidorah_testkit::fuzz::{self, Config, Outcome};

use crate::pipeline::{Load, RAW_BASE, RAW_STAGES, raw_entry, raw_seeds, root, run, work_dir};

/// The regression directory of the target, relative to the workspace root.
const REGRESS: &str = "tests/regress/pipeline_raw";

fn target(dir: &Path, input: &[u8]) -> Outcome {
    let load = Load::Raw {
        base: RAW_BASE,
        entry: raw_entry(input),
    };
    match run(dir, input, load) {
        Ok(summary) => Outcome::reached(summary.raw_stage()),
        Err(message) => Outcome::violation(0, message),
    }
}

#[test]
fn fuzz_pipeline_raw() {
    let dir = work_dir("pipeline_raw");
    let replay = fuzz::replay_regress(&root().join(REGRESS), |input| target(&dir, input))
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new("pipeline_raw", 2_000);
    config.stages = RAW_STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(root().join(REGRESS));
    config.max_len = 2 << 10;
    let report = fuzz::run(&config, &raw_seeds(), |input| target(&dir, input))
        .unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 2_000);
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
    for (stage, name) in RAW_STAGES.iter().enumerate().skip(1) {
        assert!(
            report.reached_percent(stage) >= 10,
            "stage {name}: {:?}",
            report.reached
        );
    }
}
