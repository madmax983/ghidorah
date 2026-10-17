//! `RunConfig` from the environment of a child process (design Section 10.11).

use std::path::PathBuf;

use ghidorah_cli::{Env, RunConfig};

use crate::common::{json, run_binary, tmp};

fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
    let pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

#[test]
fn runconfig_from_env_in_child() {
    let dir = tmp("runconfig");
    let root = dir.to_string_lossy().into_owned();
    let mut command = crate::common::binary(&["doctor", "--project-root", &root]);
    command
        .env("GHIDORAH_FIXED_TIME", "1700000000000")
        .env("GHIDORAH_EVAL", "1");
    let output = command.output().expect("the binary runs");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8");
    assert!(output.status.success(), "doctor passes: {stdout}");
    let report = json(stdout.trim());
    assert_eq!(
        report.get("run_config"),
        Some(&json(r#"{"fixed_time":1700000000000,"eval_mode":true}"#))
    );
    assert!(!stdout.contains(&root), "the report holds no absolute path");

    let mut command = crate::common::binary(&["doctor", "--project-root", &root]);
    command.env("GHIDORAH_EVAL", "maybe");
    let output = command.output().expect("the binary runs");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a bad variable is a usage error"
    );
    assert!(stderr.contains("GHIDORAH_EVAL"), "{stderr}");
    assert!(output.stdout.is_empty(), "a usage error writes no data");

    let fixed = run_binary(&["--version"], "");
    assert_eq!(fixed.code, 0);
}

#[test]
fn runconfig_parses_each_variable() {
    let config = RunConfig::from_lookup(&lookup(&[
        ("GHIDORAH_FIXED_TIME", "42"),
        ("GHIDORAH_EVAL", "0"),
    ]))
    .expect("the variables parse");
    assert_eq!(
        config,
        RunConfig {
            fixed_time: Some(42),
            eval_mode: false
        }
    );
    assert_eq!(config.clock().unix_ms(), 42);
    assert_eq!(config.clock().monotonic_ms(), 0);
    assert_eq!(
        config.to_json(),
        json(r#"{"fixed_time":42,"eval_mode":false}"#)
    );
    assert_eq!(
        RunConfig::from_lookup(&lookup(&[])),
        Ok(RunConfig::default())
    );
    assert_eq!(
        RunConfig::default().to_json(),
        json(r#"{"fixed_time":null,"eval_mode":false}"#)
    );
    let on = RunConfig::from_lookup(&lookup(&[("GHIDORAH_EVAL", "1")])).expect("parses");
    assert!(on.eval_mode);
    for pairs in [
        [("GHIDORAH_FIXED_TIME", "soon")],
        [("GHIDORAH_FIXED_TIME", "-1")],
        [("GHIDORAH_EVAL", "yes")],
    ] {
        let error = RunConfig::from_lookup(&lookup(&pairs)).expect_err("the value is not valid");
        assert!(error.to_string().contains(error.var), "{error}");
    }
}

#[test]
fn projects_root_follows_xdg_then_home() {
    let env = Env::from_lookup(
        PathBuf::from("/w"),
        &lookup(&[("HOME", "/home/a"), ("XDG_DATA_HOME", "/data")]),
    )
    .expect("the environment reads");
    assert_eq!(
        env.projects_root(),
        Some(PathBuf::from("/data/ghidorah/projects"))
    );
    let env = Env::from_lookup(PathBuf::from("/w"), &lookup(&[("HOME", "/home/a")]))
        .expect("the environment reads");
    assert_eq!(
        env.projects_root(),
        Some(PathBuf::from("/home/a/.local/share/ghidorah/projects"))
    );
    assert_eq!(Env::new(PathBuf::from("/w")).projects_root(), None);
}
