//! Shared helpers of the read tests: the test registry, sessions, fixtures and JSON walks.

use std::path::{Path, PathBuf};

use ghidorah_base::BinaryId;
use ghidorah_db::Program;
use ghidorah_json::{Limits, Value};
use ghidorah_testkit::fixture::cached;
use ghidorah_tools::handlers;
use ghidorah_tools::{
    AnalysisInfo, OpenBinary, Registry, Request, Roots, Session, SessionConfig, ToolSpec,
    dispatch_with,
};

/// The tools of the tests: the shipped tools and the read tools, in the `tools/list` order of
/// design Section 10.3.
pub static READ: &[&ToolSpec<Session>] = &[
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
    &handlers::session_brief::SPEC,
    &handlers::tool_search::SPEC,
    &handlers::symbol_rename::SPEC,
    &handlers::comment_set::SPEC,
    &handlers::note_write::SPEC,
    &handlers::func_edit::SPEC,
    &handlers::type_edit::SPEC,
    &handlers::history_undo::SPEC,
];

/// The read tools of WP-17b in catalog order.
pub static WP17B: &[&ToolSpec<Session>] = &[
    &handlers::survey::SPEC,
    &handlers::func_list::SPEC,
    &handlers::func_get::SPEC,
    &handlers::xref_list::SPEC,
    &handlers::search::SPEC,
    &handlers::mem_read::SPEC,
    &handlers::addr_info::SPEC,
];

/// The binary ID of the demo binary.
pub const DEMO_ID: &str = "467a43b75d95c826";

/// The registry of the tests.
pub fn registry() -> Registry<Session> {
    Registry::new(READ)
}

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives the settings of a session with the one root `base`.
pub fn config_at(base: &Path) -> SessionConfig {
    SessionConfig::new(Roots::new(base, &[PathBuf::from(".")]).expect("the root is valid"))
}

/// Gives the settings of a session with the workspace root as its root.
pub fn config() -> SessionConfig {
    config_at(&root())
}

/// Makes a session of the test registry with `config` and the analysis engine.
pub fn session_with(config: SessionConfig) -> Session {
    let mut session = Session::with_registry(
        registry(),
        config,
        Box::new(ghidorah_base::FixedClock::new(0)),
    );
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

/// Makes sure that the envelope is a success and gives its data.
pub fn data(envelope: &Value) -> &Value {
    assert_eq!(
        envelope.get("ok"),
        Some(&Value::Bool(true)),
        "the call fails: {envelope}"
    );
    envelope.get("data").expect("a success has data")
}

/// Gives the items of a successful list or targets result.
pub fn items(envelope: &Value) -> Vec<Value> {
    data(envelope)
        .get("items")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default()
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

/// Gives the text of `value` at `key`, or an empty text.
pub fn str_of(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Gives the `u64` of an address text such as `0x1080`.
pub fn addr_of(text: &str) -> u64 {
    ghidorah_base::hex::parse_u64(text).unwrap_or_else(|| panic!("{text} is an address"))
}

/// Makes a session with the demo binary open and analyzed.
pub fn demo() -> Session {
    let mut session = session();
    let envelope = call(&mut session, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(text_at(&envelope, "/data/binary_id"), DEMO_ID, "{envelope}");
    session
}

/// Gives a new empty directory for one test.
pub fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("read")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}

/// Writes `bytes` to a new file of the test `name` and loads it with `analysis`.
///
/// Gives the session, whose one root is the directory of the file, and the load envelope.
pub fn load_bytes(name: &str, bytes: &[u8], analysis: &str) -> (Session, Value) {
    let dir = tmp(name);
    std::fs::write(dir.join("input.elf"), bytes).expect("the file writes");
    let mut session = session_with(config_at(&dir));
    let args = Value::object([
        ("path", Value::from("input.elf")),
        ("analysis", Value::from(analysis)),
    ]);
    let envelope = call_value(&mut session, "binary_load", args);
    (session, envelope)
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
pub fn fixture(name: &'static str) -> (Session, String) {
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
    (session, found.id.to_string())
}

/// Gives the program of the open binary `id`.
pub fn program<'a>(session: &'a Session, id: &str) -> &'a Program {
    let id = BinaryId::parse(id).expect("a binary ID");
    &session.binary(id).expect("the binary is open").program
}

/// Leaks a name, so that it can be a cache key.
fn leak(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}

/// Gives the names of the T1 fixture binaries in name order: every file of `fixtures/bin`
/// except the T2 program `large`.
pub fn t1_fixtures() -> Vec<&'static str> {
    let mut names: Vec<String> = std::fs::read_dir(root().join("fixtures/bin"))
        .expect("the fixture directory reads")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with("large."))
        .collect();
    names.sort();
    names.into_iter().map(leak).collect()
}

/// Gives the names of the T2 fixture binaries.
pub fn t2_fixtures() -> Vec<&'static str> {
    let mut names: Vec<String> = std::fs::read_dir(root().join("fixtures/bin"))
        .expect("the fixture directory reads")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("large."))
        .collect();
    names.sort();
    names.into_iter().map(leak).collect()
}

/// Gives the names of the unstripped T1 fixtures with a truth file, in name order.
pub fn truth_fixtures() -> Vec<&'static str> {
    let mut names: Vec<String> = std::fs::read_dir(root().join("fixtures/truth"))
        .expect("the truth directory reads")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter_map(|n| n.strip_suffix(".json").map(str::to_owned))
        .filter(|n| str_of(&truth(n), "tier") == "T1")
        .collect();
    names.sort();
    names.into_iter().map(leak).collect()
}

/// Gives the truth file of the fixture `name`.
pub fn truth(name: &str) -> Value {
    let text = std::fs::read_to_string(root().join(format!("fixtures/truth/{name}.json")))
        .expect("the truth file reads");
    json(&text)
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

/// Calls `f` on `value` and on every value inside it, in document order.
pub fn walk(value: &Value, f: &mut impl FnMut(&Value)) {
    f(value);
    match value {
        Value::Array(list) => list.iter().for_each(|v| walk(v, f)),
        Value::Object(object) => object.iter().for_each(|(_, v)| walk(v, f)),
        _ => {}
    }
}

/// Tells if `value` has the one JSON shape of binary text.
pub fn is_bin_text(value: &Value) -> bool {
    value.get("src").and_then(Value::as_str) == Some("binary") && value.get("hex").is_some()
}

/// Gives the result size of an envelope in characters.
pub fn chars(envelope: &Value) -> usize {
    ghidorah_json::write(envelope).chars().count()
}
