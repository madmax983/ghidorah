//! Shared helpers of the session tests.

use std::path::PathBuf;

use ghidorah_base::{Address, BinaryId, FixedClock, Range};
use ghidorah_db::{Edit, FuncRecord, Function, SessionLabel, Source, StartReason};
use ghidorah_json::{Limits, Value};
use ghidorah_tools::handlers;
use ghidorah_tools::{
    Host, Registry, Request, Roots, Session, SessionConfig, ToolSpec, dispatch_with,
};

/// The tools of WP-13b in `tools/list` order.
pub static WP13B: &[&ToolSpec<Session>] = &[
    &handlers::load::SPEC,
    &handlers::calc::SPEC,
    &handlers::tool_search::SPEC,
];

/// The binary ID of the demo binary: the first 16 hex digits of its SHA-256.
pub const DEMO_ID: &str = "467a43b75d95c826";

/// The address of `main` in the demo binary.
pub const DEMO_MAIN: u64 = 0x1080;

/// The registry of the tests: the shipped registry. So the registry-wide tests cover every
/// registered tool.
pub fn registry() -> Registry<Session> {
    <Session as Host>::registry()
}

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives the settings of a test session: the workspace root as the one root `.`.
pub fn config() -> SessionConfig {
    SessionConfig::new(Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid"))
}

/// Makes a session with `config` over the test registry and a fixed clock.
pub fn session_with(config: SessionConfig) -> Session {
    Session::with_registry(registry(), config, Box::new(FixedClock::new(0)))
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
    envelope
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Gives the text at `pointer` of an envelope, or an empty text.
pub fn text_at(envelope: &Value, pointer: &str) -> String {
    envelope
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
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

/// Loads the file `path` under the root and gives its binary ID.
pub fn load(session: &mut Session, path: &str) -> String {
    let args = Value::object([
        ("path", Value::from(path)),
        ("analysis", Value::from("none")),
    ]);
    let envelope = call_value(session, "binary_load", args);
    text_at(&envelope, "/data/binary_id")
}

/// Makes a session with the demo binary open.
pub fn demo() -> Session {
    let mut session = session();
    let envelope = call(&mut session, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(text_at(&envelope, "/data/binary_id"), DEMO_ID, "{envelope}");
    session
}

/// Makes a session with the fixture `name` open and gives its binary ID.
pub fn fixture(name: &str) -> (Session, String) {
    let mut session = session();
    let id = load(&mut session, &format!("fixtures/bin/{name}"));
    assert!(!id.is_empty(), "the fixture {name} loads");
    (session, id)
}

/// Adds an agent function at `entry` with `size` bytes to the open binary `id`.
pub fn add_function(session: &mut Session, id: &str, entry: u64, size: u64) {
    let id = BinaryId::parse(id).expect("a binary ID");
    let binary = session.binary_mut(id).expect("the binary is open");
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = binary
        .program
        .begin("test", Source::Agent, label)
        .expect("a transaction");
    let mut func = Function::new(Address::ram(entry), StartReason::Agent, 100, Source::Agent);
    let last = entry + size - 1;
    func.body.insert(Range::new(entry, last).expect("a range"));
    let record = FuncRecord {
        func,
        vars: Vec::new(),
        plate: None,
    };
    tx.apply(Edit::CreateFunction(Box::new(record)))
        .expect("the function applies");
    tx.commit().expect("the commit works");
}
