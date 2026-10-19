//! Shared helpers of the similarity tests: the test registry, sessions with open fixtures,
//! calls and JSON reads.

use std::path::PathBuf;

use ghidorah_base::{BinaryId, FixedClock};
use ghidorah_db::Program;
use ghidorah_json::{Limits, Value};
use ghidorah_testkit::fixture::cached;
use ghidorah_tools::registry::shipped;
use ghidorah_tools::{
    AnalysisInfo, OpenBinary, Profile, ProfileSet, Registry, Request, Roots, Session,
    SessionConfig, dispatch_with, handlers,
};

/// The stripped twin of the demo binary.
pub const STRIPPED: &str = "crackme.gcc-O2.stripped";

/// The unstripped demo binary.
pub const FULL: &str = "crackme.gcc-O2";

/// Gives the registry of the tests: the shipped registry, which holds `func_similar` at its
/// catalog place.
pub fn registry() -> Registry<Session> {
    shipped()
}

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives the settings of a session with the workspace root as its one root and `profile`.
pub fn config(profile: Profile) -> SessionConfig {
    let mut config =
        SessionConfig::new(Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid"));
    config.profile = ProfileSet::new(profile, None);
    config
}

/// Makes a session of the test registry with `profile` and the analysis engine.
pub fn session_in(profile: Profile) -> Session {
    let mut session =
        Session::with_registry(registry(), config(profile), Box::new(FixedClock::new(0)));
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

/// Gives the error code of an envelope, or an empty text for a success.
pub fn code(envelope: &Value) -> String {
    text_at(envelope, "/error/code")
}

/// Gives the text at `pointer`, or an empty text.
pub fn text_at(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Gives the integer at `pointer`, or `u64::MAX`.
pub fn int_at(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX)
}

/// Gives the array at `pointer`, or an empty list.
pub fn list_at(value: &Value, pointer: &str) -> Vec<Value> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default()
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

/// Gives the `next` calls of an envelope as `(tool, args)` pairs.
pub fn next_calls(envelope: &Value) -> Vec<(String, Value)> {
    list_at(envelope, "/next")
        .iter()
        .map(|c| {
            (
                text_at(c, "/tool"),
                c.get("args").cloned().unwrap_or_default(),
            )
        })
        .collect()
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
        let mut session = session_in(Profile::Full);
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

/// Makes a session of `profile` with the analyzed fixtures `names` open, in this order. Gives
/// the session and the binary IDs.
pub fn open_in(profile: Profile, names: &[&'static str]) -> (Session, Vec<BinaryId>) {
    let mut session = session_in(profile);
    let mut ids = Vec::new();
    for name in names {
        let found = analyzed(name);
        let label = session.new_label();
        session.open(OpenBinary {
            id: found.id,
            program: found.program.clone(),
            file_name: found.file_name.clone(),
            read_only: false,
            label,
            analysis: found.analysis,
        });
        ids.push(found.id);
    }
    (session, ids)
}

/// Makes a `full` session with the analyzed fixtures `names` open.
pub fn open(names: &[&'static str]) -> (Session, Vec<BinaryId>) {
    open_in(Profile::Full, names)
}

/// Gives the program of the open binary `id`.
pub fn program(session: &Session, id: BinaryId) -> &Program {
    &session.binary(id).expect("the binary is open").program
}

/// Gives the `fn:` IDs of the functions of `id` whose names have the source `Default`, in
/// entry order.
pub fn default_named(session: &Session, id: BinaryId) -> Vec<String> {
    let p = program(session, id);
    p.funcs()
        .iter()
        .filter(|f| p.name(f.id().0).is_some_and(|n| n.is_default()))
        .map(|f| f.id().to_string())
        .collect()
}

/// Gives the `func_similar` arguments with `binary_id` and the JSON members `rest`.
pub fn similar_args(id: BinaryId, rest: &str) -> Value {
    let mut args = json(rest).as_object().cloned().unwrap_or_default();
    args.push("binary_id", Value::from(id.to_string()));
    Value::Object(args)
}
