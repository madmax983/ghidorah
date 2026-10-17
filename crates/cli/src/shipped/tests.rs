use std::collections::BTreeSet;
use std::path::PathBuf;

use ghidorah_json::Value;
use ghidorah_tools::{Profile, Session};

use super::Shipped;
use crate::backend::{Backend, LabelRule, Options};
use crate::catalog;
use crate::config::{Env, RunConfig};

/// The fixed time of the test sessions.
const TIME: u64 = 1_000;

/// Gives the options of a session in the package directory with a fixed time.
fn options() -> Options {
    let mut env = Env::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    env.run = RunConfig {
        fixed_time: Some(TIME),
        eval_mode: true,
    };
    Options::new(&env, "cli")
}

fn open(options: &Options) -> Session {
    <Shipped as Backend>::open(options).expect("the session opens")
}

fn open_error(options: &Options) -> String {
    <Shipped as Backend>::open(options)
        .expect_err("the session does not open")
        .message
}

#[test]
fn open_makes_the_session_settings() {
    let mut options = options();
    options.roots = vec![PathBuf::from("src"), PathBuf::from("tests")];
    options.read_only = true;
    options.profile = Profile::Mini;
    let session = open(&options);
    let config = session.config();
    assert_eq!(
        config.roots.names(),
        Value::Array(vec![Value::from("src"), Value::from("tests")]),
        "relative roots keep their names"
    );
    assert_eq!(config.profile.profile(), Profile::Mini);
    assert_eq!(config.profile.allowlist(), None);
    assert!(config.read_only);
    assert_eq!(
        config.run,
        ghidorah_tools::RunConfig {
            fixed_time: Some(TIME),
            eval_mode: true,
        }
    );
    assert_eq!(config.labels, LabelRule::Fixed("cli".to_owned()));
    assert_eq!(session.clock().unix_ms(), TIME);
    assert_eq!(session.new_label(), "cli");
    options.labels = LabelRule::Mcp;
    assert_eq!(open(&options).new_label(), "mcp-1");
}

#[test]
fn open_errors_name_the_cause() {
    let mut with_project = options();
    with_project.open.push("3f2a9c0d11e4b7a2".to_owned());
    assert!(open_error(&with_project).contains("3f2a9c0d11e4b7a2"));

    let mut bad_root = options();
    bad_root.roots = vec![PathBuf::from("no_such_dir")];
    assert!(open_error(&bad_root).contains("no_such_dir"));

    let mut no_roots = options();
    no_roots.roots.clear();
    assert!(open_error(&no_roots).contains("empty"));

    let mut unknown = options();
    unknown.tools = Some(BTreeSet::from([
        "calc".to_owned(),
        "nope".to_owned(),
        "zz".to_owned(),
    ]));
    let message = open_error(&unknown);
    assert!(message.contains("nope, zz"), "{message}");
    assert!(!message.contains("calc"), "{message}");

    let mut allow = options();
    allow.tools = Some(BTreeSet::from(["calc".to_owned()]));
    assert_eq!(catalog::names(&open(&allow)), ["calc"]);
}

#[test]
fn for_examples_loads_the_demo() {
    let session = Shipped::for_examples(&options()).expect("the demo loads");
    let names: Vec<&str> = session.binaries().map(|b| b.file_name.as_str()).collect();
    assert_eq!(names, [ghidorah_tools::demo::FILE_NAME]);
    let mut readonly = options();
    readonly.profile = Profile::Readonly;
    let error = Shipped::for_examples(&readonly).expect_err("readonly has no binary_load");
    assert!(error.message.contains("TOOL_NOT_IN_PROFILE"), "{error}");
}

#[test]
fn instructions_and_tools_list_follow_the_profile() {
    for profile in Profile::ALL {
        let mut options = options();
        options.profile = profile;
        let session = open(&options);
        assert_eq!(
            <Shipped as Backend>::instructions(&session),
            session.instructions()
        );
        let list = catalog::tools_list(&session);
        let tools = list
            .get("tools")
            .and_then(Value::as_array)
            .expect("a tools array");
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();
        assert_eq!(names, catalog::names(&session), "{profile:?}");
        if profile == Profile::Readonly {
            for tool in tools {
                assert_eq!(
                    tool.pointer("/annotations/readOnlyHint"),
                    Some(&Value::Bool(true)),
                    "{tool}"
                );
                assert_eq!(
                    tool.pointer("/annotations/destructiveHint"),
                    Some(&Value::Bool(false)),
                    "{tool}"
                );
            }
        }
    }
}
