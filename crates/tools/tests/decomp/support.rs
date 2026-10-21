//! Shared helpers of the decompile tests: the registry, sessions, fixtures and edits.

use std::path::PathBuf;

use ghidorah_base::BinaryId;
use ghidorah_db::{Edit, Program, Tx};
use ghidorah_json::{Limits, Value};
use ghidorah_testkit::fixture::cached;
use ghidorah_tools::handlers;
use ghidorah_tools::{
    AnalysisInfo, OpenBinary, Registry, Request, Roots, Session, SessionConfig, ToolError,
    ToolSpec, dispatch_with,
};

/// The tools of the tests in the `tools/list` order.
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
    &handlers::history_list::SPEC,
    &handlers::tool_search::SPEC,
    &handlers::history_undo::SPEC,
];

/// The registry of the tests.
pub fn registry() -> Registry<Session> {
    Registry::new(TOOLS)
}

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Makes a session of the test registry with the analysis engine and the workspace root.
pub fn session() -> Session {
    let config =
        SessionConfig::new(Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid"));
    let mut session = Session::with_registry(
        registry(),
        config,
        Box::new(ghidorah_base::FixedClock::new(0)),
    );
    handlers::analysis_run::install(&mut session);
    session
}

/// Parses JSON text.
pub fn json(text: &str) -> Value {
    ghidorah_json::parse(text, &Limits::DEFAULT).expect("the test JSON parses")
}

/// Runs one call with JSON arguments and gives the envelope JSON.
pub fn call_value(session: &mut Session, tool: &str, args: Value) -> Value {
    let registry = session.active_registry();
    dispatch_with(&registry, session, &Request::new(tool, args)).to_json()
}

/// Runs one call and gives the envelope JSON.
pub fn call(session: &mut Session, tool: &str, args: &str) -> Value {
    call_value(session, tool, json(args))
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

/// Gives the text at `pointer`, or an empty text.
pub fn text_at(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Gives the size of a value in characters.
pub fn chars(value: &Value) -> usize {
    ghidorah_json::write(value).chars().count()
}

/// One analyzed fixture.
pub struct Analyzed {
    program: Program,
    id: BinaryId,
    file_name: String,
    analysis: Option<AnalysisInfo>,
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

/// Gives the entry of the function named `name`.
pub fn entry_of(p: &Program, name: &str) -> u64 {
    p.addrs_named(name)
        .first()
        .map_or_else(|| panic!("the program names {name}"), |a| a.off)
}

/// Commits one edit through the write path of the edit tools.
pub fn commit(session: &mut Session, id: BinaryId, make: impl FnOnce(&Tx<'_>) -> Edit) {
    let _ = session
        .transact(id, "edit", "mcp-1", |tx| {
            let edit = make(tx);
            tx.apply(edit)
                .map(drop)
                .map_err(|e| ToolError::new(e.code()))
        })
        .expect("the edit commits");
}

/// Gives the decompile section of `func_get` on `target` with extra arguments `extra`.
pub fn decomp(session: &mut Session, target: &str, extra: &str) -> Value {
    let mut args = json(extra).as_object().cloned().unwrap_or_default();
    args.push("target", Value::from(target));
    args.push("include", json(r#"["decomp"]"#));
    let envelope = call_value(session, "func_get", Value::Object(args));
    data(&envelope)
        .get("decomp")
        .cloned()
        .unwrap_or_else(|| panic!("no decomp section: {envelope}"))
}

/// Gives the text of a decompile section.
pub fn text_of(section: &Value) -> String {
    text_at(section, "/text")
}

/// Gives the names of the T2 fixture binaries in name order.
pub fn t2_fixtures() -> Vec<&'static str> {
    let mut names: Vec<String> = std::fs::read_dir(root().join("fixtures/bin"))
        .expect("the fixture directory reads")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("large."))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|n| &*Box::leak(n.into_boxed_str()))
        .collect()
}
