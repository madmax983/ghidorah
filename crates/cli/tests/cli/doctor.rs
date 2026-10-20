//! `ghidorah doctor` (design Section 10.14).

use ghidorah_json::Value;
use ghidorah_tools::{Host, Session};

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
fn ac_231_doctor() {
    // The doctor of the shipped registry: every check passes on the build host.
    let env = env("doctor_shipped");
    let root = env.cwd.join("projects");
    let root_text = root.to_string_lossy().into_owned();
    let output = run_in::<Session>(&["doctor", "--project-root", &root_text], "", &env);
    assert_eq!(output.code, 0, "{}", output.stdout);
    assert_eq!(output.lines().len(), 1, "one JSON object");
    let report = json(&output.stdout);
    assert_eq!(report.get("ok"), Some(&Value::Bool(true)), "{report}");
    let checks = report
        .get("checks")
        .and_then(Value::as_array)
        .expect("the checks");
    assert!(checks.len() >= 4, "{report}");
    for c in checks {
        assert_eq!(c.get("ok"), Some(&Value::Bool(true)), "{c}");
    }
    let results = check(&report, "examples")
        .get("results")
        .and_then(Value::as_array)
        .expect("example results");
    let examples: usize = <Session as Host>::registry()
        .tools()
        .iter()
        .map(|t| t.examples.len())
        .sum();
    assert_eq!(
        results.len(),
        examples,
        "one row per example of the shipped registry"
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

#[test]
fn regress_doctor_is_hermetic() {
    // A HOME outside every git working tree, so the default projects root is valid.
    let home = std::env::temp_dir().join(format!("ghidorah-doctor-home-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("the temp HOME");
    let mut env = env("doctor_hermetic");
    env.home = Some(home.clone());
    env.xdg_data_home = None;
    let first = run_in::<Session>(&["doctor"], "", &env);
    let second = run_in::<Session>(&["doctor"], "", &env);
    let made = home.join(".local").exists();
    let _ = std::fs::remove_dir_all(&home);
    assert_eq!(first.code, 0, "{}", first.stdout);
    assert_eq!(first.stdout, second.stdout, "two runs give the same report");
    assert!(!made, "the doctor makes no projects root and no project");
}

#[test]
fn regress_doctor_refuses_root_in_git_tree() {
    let mut env = env("doctor_git_home");
    let home = env.cwd.join("home");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(home.join(".git")).expect("a git directory");
    env.home = Some(home.clone());
    env.xdg_data_home = None;
    let output = run_in::<TestHost>(&["doctor"], "", &env);
    assert_eq!(output.code, 1, "{}", output.stdout);
    let report = json(&output.stdout);
    let dir = check(&report, "project_dir");
    assert_eq!(dir.get("ok"), Some(&Value::Bool(false)), "{report}");
    assert!(
        dir.get("reason")
            .and_then(Value::as_str)
            .is_some_and(|r| r.contains("git working tree")),
        "{report}"
    );
    assert!(
        !home.join(".local").exists(),
        "the doctor makes no directory"
    );
    let home_text = home.to_string_lossy().into_owned();
    assert!(!output.stdout.contains(&home_text), "no absolute path");
}
