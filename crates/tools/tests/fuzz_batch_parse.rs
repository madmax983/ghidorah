//! Fuzz target `batch_parse` (design Section 13.5).
//!
//! This binary has one test, so the global panic hook has no race. Each case splits the input
//! into lines. It reads each line as JSON and checks it as the arguments of `batch_run` with
//! [`ghidorah_tools::batch::plan`] over the shipped registry. No step runs. A check gives a
//! plan or a tool error, never `INTERNAL_ERROR`, and it never panics. The stage of a case is
//! the highest stage of its lines, so a mutation of one line keeps the plans of the others.

#![allow(clippy::panic, reason = "a test fails through a panic")]
#![allow(clippy::expect_used, reason = "test setup uses expect")]

use std::path::PathBuf;

use ghidorah_base::ErrorCode;
use ghidorah_json::Limits;
use ghidorah_testkit::fuzz::{self, Config, Outcome};
use ghidorah_tools::batch::plan;
use ghidorah_tools::registry::shipped;
use ghidorah_tools::{ProfileSet, Registry, Session};

/// Stage 0: any input. Stage 1: JSON. Stage 2: an object. Stage 3: a plan.
const STAGES: [&str; 4] = ["input", "json", "object", "plan"];

fn regress_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/regress/batch_parse")
}

/// Checks one line of a case.
fn line(registry: &Registry<Session>, profile: &ProfileSet, input: &[u8]) -> Outcome {
    let Ok(text) = std::str::from_utf8(input) else {
        return Outcome::reached(0);
    };
    let Ok(value) = ghidorah_json::parse(text, &Limits::DEFAULT) else {
        return Outcome::reached(0);
    };
    if value.as_object().is_none() {
        return Outcome::reached(1);
    }
    match plan(registry, profile, &value) {
        Ok(_) => Outcome::reached(3),
        Err(e) if e.code == ErrorCode::InternalError => {
            Outcome::violation(2, "the check gives INTERNAL_ERROR".to_owned())
        }
        Err(_) => Outcome::reached(2),
    }
}

/// Checks each line of a case. Gives the first violation, or the highest stage.
fn target(registry: &Registry<Session>, profile: &ProfileSet, input: &[u8]) -> Outcome {
    let mut best = Outcome::reached(0);
    for part in input.split(|b| *b == b'\n') {
        let outcome = line(registry, profile, part);
        if outcome.violation.is_some() {
            return outcome;
        }
        if outcome.stage > best.stage {
            best = outcome;
        }
    }
    best
}

#[test]
fn fuzz_batch_parse() {
    let registry = shipped();
    let profile = ProfileSet::default();
    let seeds: Vec<Vec<u8>> = [
        r#"{"steps":[{"id":"s1","tool":"search","args":{"kind":"string","query":"pass","limit":5}},{"id":"s2","tool":"xref_list","args":{"targets":{"$ref":"s1","ptr":"/data/items/*/id"}},"expect":[{"ptr":"/data/items","op":"len_gt","value":0}]}],"return":["s2"]}"#,
        r#"{"steps":[{"id":"a","tool":"symbol_rename","args":{"target":"0x1090","name":"x"}}],"dry_run":true}"#,
        r#"{"steps":[{"id":"a","tool":"calc","args":{"expr":"0x1"}}],"resume":{"from_step":"a","bindings":[]}}"#,
        r#"{"steps":[{"id":"a","tool":"func_get","args":{"target":{"$ref":"a","ptr":"/data"}}}]}"#,
        r#"{"steps":[]}"#,
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    let mut corpus = seeds.clone();
    corpus.push(seeds.join(&b'\n'));
    let run = |input: &[u8]| target(&registry, &profile, input);
    let replay = fuzz::replay_regress(&regress_dir(), run)
        .unwrap_or_else(|e| panic!("replay of the regression files: {e}"));
    assert!(replay.ok(), "regression files fail: {:?}", replay.crashes);

    let mut config = Config::new("batch_parse", 2000);
    config.stages = STAGES.iter().map(|s| (*s).to_owned()).collect();
    config.pending_dir = Some(regress_dir());
    config.max_len = 4_000;
    let report =
        fuzz::run(&config, &corpus, run).unwrap_or_else(|e| panic!("the fuzz harness fails: {e}"));
    assert_eq!(report.cases, 2000);
    assert!(
        report.ok(),
        "{} panics, {} violations: {:?}",
        report.panics,
        report.violations,
        report.crashes
    );
    assert_eq!(fuzz::panic_count(), 0, "no case panics");
    assert!(report.reached[3] > 0, "plan share: {:?}", report.reached);
}
