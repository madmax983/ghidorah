//! `ghidorah doctor` (design Section 10.14).

use ghidorah_json::Value;

use crate::common::registry::TestHost;
use crate::common::{env, json, run_in};

fn check<'a>(report: &'a Value, name: &str) -> &'a Value {
    report
        .get("checks")
        .and_then(Value::as_array)
        .and_then(|checks| {
            checks
                .iter()
                .find(|c| c.get("name").and_then(Value::as_str) == Some(name))
        })
        .unwrap_or_else(|| panic!("the report has the check {name}: {report}"))
}

#[test]
fn doctor_reports_checks() {
    let env = env("doctor");
    let root = env.cwd.join("projects");
    let root_text = root.to_string_lossy().into_owned();
    let output = run_in::<TestHost>(&["doctor", "--project-root", &root_text], "", &env);
    assert_eq!(output.code, 0, "{}", output.stdout);
    assert_eq!(output.lines().len(), 1, "one JSON object");
    let report = json(&output.stdout);
    assert_eq!(report.get("ok"), Some(&Value::Bool(true)));
    for name in ["registry_lint", "examples", "project_dir", "era"] {
        assert_eq!(
            check(&report, name).get("ok"),
            Some(&Value::Bool(true)),
            "{name}"
        );
    }
    let sizes = check(&report, "examples")
        .get("results")
        .and_then(Value::as_array)
        .expect("example results");
    assert_eq!(sizes.len(), 4, "one row per example");
    for row in sizes {
        for mode in ["plain", "structured", "text", "both"] {
            let chars = row
                .pointer(&format!("/chars/{mode}"))
                .and_then(Value::as_u64);
            assert!(chars.is_some_and(|c| c > 0 && c <= 60_000), "{row}");
        }
    }
    assert!(!output.stdout.contains(&root_text), "no absolute path");
    assert!(
        !root.join(ghidorah_cli::doctor::PROBE).exists(),
        "the probe file is gone"
    );
}

#[test]
fn doctor_fails_without_a_projects_root() {
    let output = run_in::<TestHost>(&["doctor"], "", &env("doctor_none"));
    assert_eq!(output.code, 1, "{}", output.stdout);
    let report = json(&output.stdout);
    assert_eq!(report.get("ok"), Some(&Value::Bool(false)));
    assert_eq!(
        check(&report, "project_dir").get("ok"),
        Some(&Value::Bool(false))
    );
}
