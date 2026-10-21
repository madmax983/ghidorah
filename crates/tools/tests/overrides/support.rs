//! Shared helpers of the override tests: the test registry, sessions, projects and JSON walks.

use std::path::{Path, PathBuf};

use ghidorah_base::{BinaryId, FixedClock};
use ghidorah_db::Program;
use ghidorah_json::{Limits, Value};
use ghidorah_tools::session::ProjectsConfig;
use ghidorah_tools::{
    Registry, Request, Roots, Session, SessionConfig, ToolSpec, dispatch_with, handlers,
};

/// The binary ID of the demo binary.
pub const DEMO_ID: &str = "467a43b75d95c826";

/// The tools of the tests: the shipped tools and the tools of WP-22b, in the `tools/list`
/// order of design Section 10.3.
pub static TOOLS: &[&ToolSpec<Session>] = &[
    &handlers::load::SPEC,
    &handlers::survey::SPEC,
    &handlers::analysis_run::SPEC,
    &handlers::func_list::SPEC,
    &handlers::func_get::SPEC,
    &handlers::xref_list::SPEC,
    &handlers::search::SPEC,
    &handlers::mem_read::SPEC,
    &handlers::addr_info::SPEC,
    &handlers::calc::SPEC,
    &handlers::type_get::SPEC,
    &handlers::history_list::SPEC,
    &handlers::tool_search::SPEC,
    &handlers::func_edit::SPEC,
    &handlers::type_edit::SPEC,
    &handlers::history_undo::SPEC,
];

/// The tools of WP-22b in catalog order.
pub static WP22B: &[&ToolSpec<Session>] = &[
    &handlers::type_get::SPEC,
    &handlers::func_edit::SPEC,
    &handlers::type_edit::SPEC,
];

/// Gives the registry of the tests.
pub fn registry() -> Registry<Session> {
    Registry::new(TOOLS)
}

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives the settings of a session with the workspace root as its root.
pub fn config() -> SessionConfig {
    SessionConfig::new(Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid"))
}

/// Gives the settings of a session with the projects root `dir`.
pub fn config_in(dir: &Path) -> SessionConfig {
    let mut config = config();
    config.projects = Some(ProjectsConfig {
        root: dir.to_path_buf(),
        named: true,
        break_lock: false,
    });
    config
}

/// Makes a session of the test registry with `config` and the analysis engine.
pub fn session_with(config: SessionConfig) -> Session {
    let mut session = Session::with_registry(registry(), config, Box::new(FixedClock::new(0)));
    handlers::analysis_run::install(&mut session);
    session
}

/// Parses JSON text.
pub fn json(text: &str) -> Value {
    ghidorah_json::parse(text, &Limits::DEFAULT).expect("the test JSON parses")
}

/// Runs one call and gives the envelope JSON.
pub fn call(session: &mut Session, tool: &str, args: &str) -> Value {
    call_value(session, tool, json(args))
}

/// Runs one call with JSON arguments and gives the envelope JSON.
pub fn call_value(session: &mut Session, tool: &str, args: Value) -> Value {
    let registry = session.active_registry();
    dispatch_with(&registry, session, &Request::new(tool, args)).to_json()
}

/// Gives the text at `pointer` of a value, or an empty text.
pub fn text_at(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Gives the error code of an envelope, or an empty text for a success.
pub fn code(envelope: &Value) -> String {
    text_at(envelope, "/error/code")
}

/// Makes sure that the envelope is a success and gives its data.
pub fn data(envelope: &Value) -> &Value {
    assert_eq!(
        envelope.get("ok"),
        Some(&Value::Bool(true)),
        "the call fails: {envelope}"
    );
    envelope.get("data").expect("a success has data")
}

/// Gives the items of a successful list result.
pub fn items(envelope: &Value) -> Vec<Value> {
    data(envelope)
        .get("items")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default()
}

/// Gives the warnings of `code` in an envelope.
pub fn warnings<'a>(envelope: &'a Value, code: &str) -> Vec<&'a Value> {
    envelope
        .get("warnings")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter(|w| w.get("code").and_then(Value::as_str) == Some(code))
        .collect()
}

/// Gives the codes of the caveats of the function `target` from `func_get`.
pub fn caveats(session: &mut Session, target: &str) -> Vec<Value> {
    let args = Value::object([("target", Value::from(target))]);
    let envelope = call_value(session, "func_get", args);
    data(&envelope)
        .get("caveats")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default()
}

/// Loads the demo binary in `session`.
pub fn load_demo(session: &mut Session) -> BinaryId {
    let envelope = call(session, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(text_at(&envelope, "/data/binary_id"), DEMO_ID, "{envelope}");
    BinaryId::parse(DEMO_ID).expect("the ID parses")
}

/// Makes a session with the demo binary open and analyzed.
pub fn demo() -> Session {
    let mut session = session_with(config());
    load_demo(&mut session);
    session
}

/// Gives the program of the demo binary of `session`.
pub fn program(session: &Session) -> &Program {
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    &session.binary(id).expect("the demo is open").program
}

/// Gives a new empty directory for one test.
pub fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("overrides")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}
