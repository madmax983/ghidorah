//! The fuzz harness finds a planted bug in a small TLV parser.
//!
//! This binary has one test, so the global panic hook has no race.

#![allow(clippy::panic, reason = "a test fails through a panic")]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use ghidorah_testkit::fuzz::{self, Config, Outcome};
use ghidorah_testkit::pbt;

/// Parses `tag, len, value[len]` records.
///
/// Stage 0: the input is not empty. Stage 1: one record parsed. Stage 2: a tag 7 record.
/// The planted bug: a tag 7 record with length 0 reads `value[0]` and panics.
fn parse_tlv(input: &[u8]) -> Outcome {
    let mut stage = 0;
    let mut pos = 0usize;
    let mut records = 0u32;
    while pos < input.len() && records < 64 {
        let Some(&tag) = input.get(pos) else { break };
        let Some(&len) = input.get(pos + 1) else {
            break;
        };
        let start = pos + 2;
        let end = start + usize::from(len);
        let Some(value) = input.get(start..end) else {
            break;
        };
        stage = stage.max(1);
        if tag == 7 {
            stage = 2;
            let first = value[0];
            if first == 0xff {
                return Outcome::violation(stage, "tag 7 with value 0xff".to_string());
            }
        }
        pos = end;
        records += 1;
    }
    Outcome::reached(stage)
}

fn panics(input: &[u8]) -> bool {
    catch_unwind(AssertUnwindSafe(|| parse_tlv(input))).is_err()
}

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fuzz_tlv_regress")
}

#[test]
fn fuzz_finds_tlv_bug() {
    let corpus = vec![vec![1, 2, 0xaa, 0xbb, 7, 1, 0x05], vec![3, 0]];
    let mut config = Config::new("tlv", 2000);
    config.stages = vec!["input".into(), "record".into(), "tag7".into()];
    let report = fuzz::run(&config, &corpus, parse_tlv);
    let Ok(report) = report else {
        panic!("the harness itself fails: {report:?}");
    };
    assert_eq!(report.cases, 2000);
    assert!(report.panics > 0, "the planted bug panics: {report:?}");
    assert!(!report.ok());
    assert!(!report.crashes.is_empty());
    assert!(report.crashes.len() <= config.max_crashes);
    assert!(
        report.crashes.windows(2).all(|w| w[0].case < w[1].case),
        "the report keeps the first crashes in case order"
    );
    assert!(
        fuzz::panic_count() >= report.panics,
        "the hook counts each panic"
    );
    for crash in &report.crashes {
        assert!(
            panics(&crash.input) || parse_tlv(&crash.input).violation.is_some(),
            "each crash reproduces: {crash:?}"
        );
    }
    // Each case counts for its deepest stage and every stage before it.
    assert_eq!(report.reached.len(), 3);
    assert!(report.reached_percent(0) >= 90, "{:?}", report.reached);
    assert!(
        report.reached[0] >= report.reached[1],
        "{:?}",
        report.reached
    );
    assert!(
        report.reached[1] >= report.reached[2],
        "{:?}",
        report.reached
    );
    assert!(report.reached[2] > 0, "{:?}", report.reached);

    // The same seed gives the same report.
    let again = fuzz::run(&config, &corpus, parse_tlv);
    assert_eq!(again.as_ref().ok(), Some(&report));

    // The crash shrinks to the minimal input.
    let first = report
        .crashes
        .iter()
        .find(|c| panics(&c.input))
        .map(|c| c.input.clone());
    let Some(first) = first else {
        panic!("one crash is a panic");
    };
    let minimal = pbt::shrink_bytes(&first, panics);
    assert_eq!(minimal, vec![7, 0]);

    // A regression file replays as a failure.
    let dir = regress_dir();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    std::fs::write(dir.join("0123abcd.bin"), &minimal)
        .unwrap_or_else(|e| panic!("write the regression file: {e}"));
    std::fs::write(dir.join("ok.bin"), [1u8, 1, 1])
        .unwrap_or_else(|e| panic!("write the passing file: {e}"));
    let replay = fuzz::replay_regress(&dir, parse_tlv);
    let Ok(replay) = replay else {
        panic!("replay fails: {replay:?}");
    };
    assert_eq!(replay.cases, 2);
    assert_eq!(replay.panics, 1);
    assert_eq!(replay.crashes.len(), 1);
    assert_eq!(replay.crashes[0].input, vec![7, 0]);

    let missing = fuzz::replay_regress(&dir.join("missing"), parse_tlv);
    assert_eq!(missing.map(|r| r.cases), Ok(0));
}
