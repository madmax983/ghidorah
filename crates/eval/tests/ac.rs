//! The acceptance tests of the eval harness (design Section 12, WP-26).
//!
//! One eval run serves every test: the first test that needs it runs it, the others wait.
//! `ac_200_eval_deterministic` makes a second run and compares the two scorecards.
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "the helpers fail the calling test with a message"
)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ghidorah_eval::gate::{self, Blessing};
use ghidorah_eval::inputs::{self, CATEGORY_MINIMUMS, MIN_SCENARIOS, Metric, THRESHOLDS};
use ghidorah_eval::milli::Milli;
use ghidorah_eval::repair::MIN_MISTAKES;
use ghidorah_eval::scorecard::schema;
use ghidorah_eval::{EvalError, Report, evaluate, host, lint, runner, scenario, sha256};
use ghidorah_json::Value;
use ghidorah_testkit::golden::{self, Header};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn report() -> &'static Report {
    static REPORT: OnceLock<Report> = OnceLock::new();
    REPORT.get_or_init(|| evaluate(&root()).expect("the eval runs"))
}

/// Gives the gate value of the metric `name`: `max(floor, baseline - tolerance)`.
fn bar(name: &str) -> Milli {
    let metric: Metric = report()
        .thresholds
        .metrics
        .get(name)
        .copied()
        .unwrap_or_else(|| panic!("{THRESHOLDS} has no metric {name}"));
    gate::bar(&metric)
}

fn metric(name: &str) -> Milli {
    report().metrics().get(name).copied().unwrap_or_default()
}

fn sha_of(rel: &str) -> String {
    sha256::hex(&std::fs::read(root().join(rel)).expect("the file reads"))
}

#[test]
fn ac_153b_survey_recall() {
    let survey = &report().survey;
    assert!(
        survey.fixtures.len() >= 18,
        "{} T1 fixtures",
        survey.fixtures.len()
    );
    let rate = survey.rate();
    assert!(
        rate >= bar("survey_fact_recall"),
        "survey recall {rate}: {survey:?}"
    );
}

#[test]
fn ac_195_scenarios() {
    let r = report();
    assert_eq!(
        sha_of(inputs::QUESTIONS),
        r.thresholds.questions_sha256,
        "the questions are hash-locked"
    );
    assert!(
        r.scenarios.len() >= MIN_SCENARIOS,
        "{} scenarios",
        r.scenarios.len()
    );
    for (category, min) in CATEGORY_MINIMUMS {
        let n = r
            .outcomes
            .iter()
            .filter(|o| o.category == *category)
            .count();
        assert!(
            n >= *min,
            "category {category} has {n} scenarios, the minimum is {min}"
        );
    }
    for q in &r.questions {
        assert!(
            r.scenarios.iter().any(|s| s.question == q.id),
            "no scenario answers {}",
            q.id
        );
    }
    let failed: Vec<String> = r
        .outcomes
        .iter()
        .chain(&r.ab_outcomes)
        .filter(|o| !o.pass)
        .map(|o| format!("{}: {:?} {:?}", o.id, o.error, o.answer))
        .collect();
    assert!(failed.is_empty(), "failed scenarios: {failed:#?}");
}

#[test]
fn ac_196a_cost_gate() {
    let costs = gate::read_costs(&root()).expect("the cost baselines read");
    let findings = report().cost_findings(&costs);
    assert!(findings.is_empty(), "cost findings: {findings:#?}");
}

#[test]
fn ac_196b_bless_log() {
    let r = report();
    let costs = gate::read_costs(&root()).expect("the cost baselines read");
    let log = gate::read_log(&root()).expect("the bless log reads");
    let findings = gate::log_findings(&r.thresholds, &costs, &log);
    assert!(findings.is_empty(), "bless-log findings: {findings:#?}");
    // A bless refuses to run over a lowered floor, and it writes nothing.
    let mut lowered = r.thresholds.clone();
    if let Some(m) = lowered.metrics.get_mut("discoverability") {
        m.floor = Some(Milli(500));
    }
    let scratch = host::Scratch::new("bless").expect("a scratch directory");
    let result = gate::bless(
        scratch.path(),
        &lowered,
        &Blessing::default(),
        "c0ffee",
        "test",
    );
    assert!(matches!(result, Err(EvalError::Bless { .. })), "{result:?}");
    assert!(
        !scratch.path().join(gate::BLESS_LOG).exists(),
        "a refused bless writes no log"
    );
}

#[test]
fn ac_197_repair_rate() {
    let repair = &report().repair;
    assert!(
        repair.attempts.len() >= MIN_MISTAKES,
        "{} mistakes",
        repair.attempts.len()
    );
    let silent: Vec<&str> = repair
        .attempts
        .iter()
        .filter(|a| !a.triggered)
        .map(|a| a.id.as_str())
        .collect();
    assert!(
        silent.is_empty(),
        "mistakes that do not give their code: {silent:?}"
    );
    assert_eq!(
        repair.rate("R"),
        Milli::ONE,
        "R codes: {:?}",
        repair.by_code()
    );
    assert_eq!(
        repair.rate("C"),
        Milli::ONE,
        "C codes: {:?}",
        repair.by_code()
    );
    assert!(
        repair
            .by_code()
            .values()
            .any(|row| row.class == "H" && !row.ranks.is_empty())
    );
}

#[test]
fn ac_198a_discoverability() {
    let d = &report().discover;
    assert!(d.intents >= 40, "{} held-out intents", d.intents);
    assert!(d.tool_search_top3() >= bar("discoverability"), "{d:?}");
}

#[test]
fn ac_198b_intents_hash() {
    let t = inputs::read_thresholds(&root()).expect("the thresholds read");
    assert_eq!(sha_of(inputs::INTENTS_HELDOUT), t.intents_sha256);
}

#[test]
fn ac_199_context_reset() {
    let recall = &report().recall_reset;
    assert!(recall.total >= 6, "{recall:?}");
    assert!(recall.rate() >= bar("context_reset_recall"), "{recall:?}");
}

#[test]
fn ac_200_eval_deterministic() {
    let first = ghidorah_json::write(&report().scorecard());
    let second =
        ghidorah_json::write(&evaluate(&root()).expect("the second eval runs").scorecard());
    assert_eq!(first, second, "two eval runs give byte-equal scorecards");
    let shape = ghidorah_json::write_pretty(&schema(&report().scorecard()));
    let path = root().join("tests/golden/eval/scorecard.schema.json");
    let header = Header::new("ghidorah-eval", "1");
    if let Err(e) = golden::compare(&path, &header, &shape, golden::bless_from_env()) {
        panic!("{e}");
    }
    assert_eq!(
        metric("determinism"),
        Milli::ONE,
        "{:?}",
        report().nondeterministic()
    );
}

#[test]
fn ac_226_provenance_lint() {
    let (values, findings) = report().provenance();
    assert!(values >= 150, "{values} linted values");
    assert!(findings.is_empty(), "provenance findings: {findings:#?}");
    // The same script with one hard-coded address fails the lint.
    let r = report();
    let (i, s) = r
        .scenarios
        .iter()
        .enumerate()
        .find(|(_, s)| s.id == "locate-04")
        .expect("the scenario locate-04 exists");
    let mut bad = s.clone();
    if let Some(turn) = bad.turns.get_mut(2) {
        turn.args = ghidorah_json::parse(
            r#"{"target":"0x11d0","as":"insn","count":2}"#,
            &ghidorah_json::Limits::DEFAULT,
        )
        .expect("the arguments parse");
    }
    let q = r
        .questions
        .iter()
        .find(|q| q.id == s.question)
        .expect("the question exists");
    let outcome = r.outcomes.get(i).expect("the outcome exists");
    let found = lint::lint(&bad, q, outcome, "");
    assert!(
        found
            .findings
            .iter()
            .any(|f| f.path == "/turns/2/call/args/target"),
        "{found:?}"
    );
}

#[test]
fn ac_227_hint_follower() {
    let f = &report().follower;
    assert!(f.walks.len() >= 10, "{} walks", f.walks.len());
    assert!(f.rate() >= bar("hint_follower_reach"), "{f:?}");
}

#[test]
fn ac_228_abstain() {
    let r = report();
    let abstains = r.abstains();
    assert!(abstains.len() >= 4, "{} abstain scenarios", abstains.len());
    for o in &abstains {
        assert!(o.pass, "{}: {:?} {:?}", o.id, o.error, o.answer);
        assert!(
            !o.responses.iter().any(runner::overclaims),
            "{} overclaims",
            o.id
        );
    }
    let refuted = ghidorah_json::parse(
        r#"{"data":{"verdicts":[{"verdict":"refuted"}]}}"#,
        &ghidorah_json::Limits::DEFAULT,
    )
    .expect("the JSON parses");
    let empty = ghidorah_json::parse(
        r#"{"data":{"items":[],"basis":{"complete":true}}}"#,
        &ghidorah_json::Limits::DEFAULT,
    )
    .expect("the JSON parses");
    assert!(runner::overclaims(&refuted) && runner::overclaims(&empty));
    assert_eq!(metric("abstain_correctness"), Milli::ONE);
}

#[test]
fn ac_229_recall_after_edits() {
    let recall = &report().recall_edits;
    assert_eq!(recall.noise, 50, "{recall:?}");
    assert!(recall.rate() >= bar("recall_after_edits"), "{recall:?}");
}

#[test]
fn ac_230_restart_resume() {
    let r = report();
    let restarts: Vec<_> = r
        .scenarios
        .iter()
        .zip(&r.outcomes)
        .filter(|(s, o)| o.category == "resume" && s.turns.iter().any(|t| t.restart))
        .collect();
    assert!(
        !restarts.is_empty(),
        "no resume scenario restarts the server"
    );
    for (s, o) in restarts {
        assert!(o.pass, "{}: {:?} {:?}", s.id, o.error, o.answer);
        let restart = s.turns.iter().position(|t| t.restart).unwrap_or(0);
        assert_eq!(
            s.turns.get(restart).map(|t| t.tool.as_str()),
            Some("session_brief")
        );
    }
}

/// Every scenario file names a question, and an A/B file names its single-call scenario.
#[test]
fn scenario_files_name_their_question() {
    let r = report();
    for s in r.scenarios.iter().chain(&r.ab_scenarios) {
        assert!(r.questions.iter().any(|q| q.id == s.question), "{}", s.file);
    }
    for s in &r.ab_scenarios {
        let pair = s.pair.as_deref().unwrap_or_default();
        assert!(
            r.scenarios
                .iter()
                .any(|x| x.id == pair && x.question == s.question),
            "{}",
            s.file
        );
    }
    assert_eq!(
        scenario::read_dir(Path::new(&root()), scenario::DIR)
            .map(|v| v.len())
            .ok(),
        Some(r.scenarios.len())
    );
}

/// The scorecard holds the members of design Section 12.5.
#[test]
fn scorecard_members() {
    let card = report().scorecard();
    for key in [
        "scenarios",
        "provenance",
        "repair",
        "hint_follower",
        "discoverability",
        "determinism",
        "recall",
        "survey_recall",
        "abstain",
        "metamorphic",
        "fuzz",
        "catalog",
        "ablation",
        "ab",
    ] {
        assert!(card.get(key).is_some(), "the scorecard has no {key}");
    }
    let failed: Vec<&Value> = card
        .get("gates")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter(|g| g.get("pass") != Some(&Value::Bool(true)))
        .collect();
    assert!(failed.is_empty(), "failed gates: {failed:?}");
}
