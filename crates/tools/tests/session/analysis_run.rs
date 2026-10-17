//! `analysis_run`: fuel slices, resume, the analyzer table, the change counts and dry runs.

use ghidorah_json::Value;
use ghidorah_tools::handlers::analysis_run::{self, SLICE_STEPS};

use crate::support::{call, data, fixture, text_at};

fn int(v: &Value, pointer: &str) -> u64 {
    v.pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX)
}

#[test]
fn analysis_run_completes_and_reports() {
    let (mut s, id) = fixture("noreturn_wrappers.gcc-O2");
    let envelope = call(&mut s, "analysis_run", "{}");
    let got = data(&envelope);
    assert_eq!(text_at(got, "/state"), "complete");
    assert_eq!(got.get("resume"), Some(&Value::Bool(false)));
    assert!(int(got, "/steps_used") > 0);
    assert!(int(got, "/changed/functions") > 10);
    assert!(int(got, "/changed/refs") > 10);
    assert_eq!(int(got, "/changed/strings"), 0);
    let rows = got
        .get("analyzers")
        .and_then(Value::as_array)
        .expect("rows");
    let names: Vec<&str> = rows
        .iter()
        .filter_map(|r| r.get("name").and_then(Value::as_str))
        .collect();
    assert_eq!(
        names,
        [
            "Entry",
            "Symbols",
            "ImportStubs",
            "FdeSeeds",
            "Disasm",
            "NoReturnKnown",
            "NoReturnDiscovered",
            "CallTargets",
            "EndbrSeeds"
        ]
    );
    assert!(rows.iter().all(|r| int(r, "/pending") == 0));
    assert_eq!(envelope.get("partial"), Some(&Value::Bool(false)));
    assert_eq!(text_at(&envelope, "/binary_id"), id);
    assert_eq!(int(&envelope, "/rev"), 1, "one publish commit");

    let again = call(&mut s, "analysis_run", "{}");
    let got = data(&again);
    assert_eq!(int(got, "/steps_used"), 0);
    assert_eq!(int(got, "/changed/functions"), 0);
    assert_eq!(again.get("noop"), Some(&Value::Bool(true)));
    assert_eq!(int(&again, "/rev"), 1);
}

#[test]
fn analysis_run_resumes_after_a_budget_stop() {
    let (mut s, _) = fixture("large.gcc-O2");
    let first = call(&mut s, "analysis_run", r#"{"max_steps":10}"#);
    let got = data(&first);
    assert_eq!(text_at(got, "/state"), "budget_stopped");
    assert_eq!(got.get("resume"), Some(&Value::Bool(true)));
    assert!(int(got, "/steps_used") >= 10);
    assert!(int(got, "/steps_used") < SLICE_STEPS * 4);
    assert_eq!(first.get("partial"), Some(&Value::Bool(true)));
    assert_eq!(text_at(&first, "/next/0/tool"), "analysis_run");
    let pending: u64 = got
        .get("analyzers")
        .and_then(Value::as_array)
        .expect("rows")
        .iter()
        .map(|r| int(r, "/pending"))
        .sum();
    assert!(pending > 0);

    let dry = call(&mut s, "analysis_run", r#"{"dry_run":true}"#);
    assert_eq!(int(data(&dry), "/steps_used"), 0);
    assert_eq!(text_at(data(&dry), "/state"), "budget_stopped");
    assert_eq!(dry.get("noop"), Some(&Value::Bool(true)));

    let rest = call(&mut s, "analysis_run", "{}");
    assert_eq!(text_at(data(&rest), "/state"), "complete");
    assert_eq!(rest.get("partial"), Some(&Value::Bool(false)));
}

#[test]
fn analysis_run_triage_and_an_installed_engine() {
    let (mut s, _) = fixture("hello.gcc-O2");
    analysis_run::install(&mut s);
    let got = call(&mut s, "analysis_run", r#"{"until":"triage"}"#);
    assert_eq!(text_at(data(&got), "/state"), "complete");
    let load = call(
        &mut s,
        "binary_load",
        r#"{"path":"fixtures/bin/two_helpers.gcc-O2"}"#,
    );
    assert_eq!(
        text_at(data(&load), "/analysis/state"),
        "complete",
        "binary_load runs the installed engine"
    );
}
