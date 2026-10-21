//! Shared helpers of the memory tests: the test registry, sessions, fixtures and JSON walks.

use std::path::{Path, PathBuf};

use ghidorah_base::{BinaryId, FixedClock};
use ghidorah_db::Program;
use ghidorah_json::{Limits, Value};
use ghidorah_testkit::fixture::cached;
use ghidorah_tools::handlers;
use ghidorah_tools::session::{LabelRule, ProjectsConfig};
use ghidorah_tools::{
    AnalysisInfo, OpenBinary, Registry, Request, Roots, Session, SessionConfig, ToolSpec,
    dispatch_with,
};

/// The tools of the tests: the shipped tools and the memory tools, in the `tools/list` order of
/// design Section 10.3.
pub static MEMORY: &[&ToolSpec<Session>] = &[
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
    &handlers::history_list::SPEC,
    &handlers::session_brief::SPEC,
    &handlers::tool_search::SPEC,
    &handlers::symbol_rename::SPEC,
    &handlers::comment_set::SPEC,
    &handlers::note_write::SPEC,
    &handlers::history_undo::SPEC,
];

/// The tools of WP-22a in catalog order.
pub static WP22A: &[&ToolSpec<Session>] = &[
    &handlers::session_brief::SPEC,
    &handlers::symbol_rename::SPEC,
    &handlers::comment_set::SPEC,
    &handlers::note_write::SPEC,
];

/// The binary ID of the demo binary.
pub const DEMO_ID: &str = "467a43b75d95c826";

/// The stripped twin of the demo binary: its functions have default names.
pub const STRIPPED: &str = "crackme.gcc-O2.stripped";

/// The registry of the tests.
pub fn registry() -> Registry<Session> {
    Registry::new(MEMORY)
}

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives the settings of a session with the workspace root as its one root.
pub fn config() -> SessionConfig {
    SessionConfig::new(Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid"))
}

/// Gives the settings of a session with the projects root `dir` and `mcp-` labels.
pub fn config_in(dir: &Path) -> SessionConfig {
    let mut config = config();
    config.labels = LabelRule::Mcp;
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

/// Makes a session with no open binary.
pub fn session() -> Session {
    session_with(config())
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

/// Gives the error code of an envelope, or an empty text for a success.
pub fn code(envelope: &Value) -> String {
    text_at(envelope, "/error/code")
}

/// Gives the text at `pointer` of an envelope, or an empty text.
pub fn text_at(envelope: &Value, pointer: &str) -> String {
    envelope
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Gives the integer at `pointer` of an envelope, or `u64::MAX`.
pub fn int_at(envelope: &Value, pointer: &str) -> u64 {
    envelope
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX)
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

/// Gives the text of `value` at `key`, or an empty text.
pub fn str_of(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Gives the `id` of each item of a list envelope.
pub fn ids(envelope: &Value) -> Vec<String> {
    items(envelope).iter().map(|i| str_of(i, "id")).collect()
}

/// Gives the number of warnings of `code` in an envelope.
pub fn warnings(envelope: &Value, code: &str) -> usize {
    envelope
        .get("warnings")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter(|w| w.get("code").and_then(Value::as_str) == Some(code))
        .count()
}

/// Gives the first `next` call of an envelope: its tool and its arguments.
pub fn next0(envelope: &Value) -> (String, Value) {
    let call = envelope
        .pointer("/next/0")
        .unwrap_or_else(|| panic!("the envelope has no next call: {envelope}"));
    (
        str_of(call, "tool"),
        call.get("args").cloned().unwrap_or_default(),
    )
}

/// Makes a session with the demo binary open and analyzed.
pub fn demo() -> Session {
    let mut session = session();
    let envelope = call(&mut session, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(text_at(&envelope, "/data/binary_id"), DEMO_ID, "{envelope}");
    session
}

/// Gives the binary ID of the demo binary.
pub fn demo_id() -> BinaryId {
    BinaryId::parse(DEMO_ID).expect("the ID parses")
}

/// Gives a new empty directory for one test.
pub fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("memory")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}

/// One analyzed fixture.
pub struct Analyzed {
    /// The program after the default load.
    pub program: Program,
    /// The binary ID.
    pub id: BinaryId,
    /// The file name.
    pub file_name: String,
    /// The analysis state after the load.
    pub analysis: Option<AnalysisInfo>,
}

/// Gives the analyzed program of the fixture `name`. Each test binary loads it once.
pub fn analyzed(name: &'static str) -> &'static Analyzed {
    cached(name, || {
        let mut session = session();
        let args = Value::object([("path", Value::from(format!("fixtures/bin/{name}")))]);
        let envelope = call_value(&mut session, "binary_load", args);
        let id = BinaryId::parse(&text_at(&envelope, "/data/binary_id"))
            .unwrap_or_else(|_| panic!("{name} loads: {envelope}"));
        let binary = session.binary(id).expect("the fixture is open");
        Analyzed {
            program: binary.program.clone(),
            id,
            file_name: binary.file_name.clone(),
            analysis: binary.analysis,
        }
    })
}

/// Makes a session with the analyzed fixture `name` open. Gives the session and the ID.
pub fn fixture(name: &'static str) -> (Session, BinaryId) {
    let found = analyzed(name);
    let mut session = session();
    let label = session.new_label();
    session.open(OpenBinary {
        id: found.id,
        program: found.program.clone(),
        file_name: found.file_name.clone(),
        read_only: false,
        label,
        analysis: found.analysis,
    });
    (session, found.id)
}

/// Gives the program of the open binary `id`.
pub fn program(session: &Session, id: BinaryId) -> &Program {
    &session.binary(id).expect("the binary is open").program
}

/// Gives every item of a list call: the call pages with `limit` until no cursor is left.
pub fn all_items(session: &mut Session, tool: &str, args: &Value, limit: u32) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10_000 {
        let mut object = args.as_object().cloned().unwrap_or_default();
        object.push("limit", Value::from(limit));
        if let Some(c) = &cursor {
            object.push("cursor", Value::from(c.as_str()));
        }
        let envelope = call_value(session, tool, Value::Object(object));
        out.extend(items(&envelope));
        cursor = envelope
            .pointer("/page/next_cursor")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if cursor.is_none() {
            return out;
        }
    }
    panic!("the pages of {tool} do not end");
}

/// Gives the result size of an envelope in characters.
pub fn chars(envelope: &Value) -> usize {
    ghidorah_json::write(envelope).chars().count()
}
