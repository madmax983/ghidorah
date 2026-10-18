//! Shared helpers of the batch tests: the registry, sessions, calls and JSON reads.
//!
//! The registry of the tests is the shipped registry with `batch_run` at its catalog place.
//! When the shipped registry has no `fact_check`, a test `fact_check` takes its place, so the
//! claim guards have a relation tool. After the register commits, the shipped registry holds
//! both tools, and the tests use it as it is.

use std::path::PathBuf;
use std::sync::OnceLock;

use ghidorah_base::{BinaryId, FixedClock};
use ghidorah_db::Program;
use ghidorah_json::{Limits, Object, Value};
use ghidorah_testkit::fixture::cached;
use ghidorah_tools::outshape::Field;
use ghidorah_tools::registry::shipped;
use ghidorah_tools::{
    AnalysisInfo, ArgKind, ArgSpec, Args, Ctx, Example, OpenBinary, OutputShape, Payload, Profile,
    ProfileSet, Registry, Request, Role, Roots, Session, SessionConfig, ToolError, ToolSpec,
    dispatch_with, handlers,
};

/// The binary ID of the demo binary.
pub const DEMO_ID: &str = "467a43b75d95c826";

/// The claim that the test `fact_check` supports: `main` calls `check_password`.
pub const TRUE_CALL: [&str; 2] = ["fn:0x1080", "fn:0x11e0"];

const CLAIM_ARGS: &[ArgSpec] = &[ArgSpec::new(
    "claims",
    Role::Param,
    ArgKind::Json,
    "The claims of the test.",
)];

/// A test `fact_check` for a registry without the real tool. It supports only the claim
/// `calls(fn:0x1080, fn:0x11e0)`, and it refutes every other claim.
pub const TEST_FACT_CHECK: ToolSpec<Session> = ToolSpec {
    title: "Check facts in a test",
    summary: "Check fact claims of a test with supported or refuted verdicts.",
    description: "Check fact claims of a test with supported or refuted verdicts.",
    args: CLAIM_ARGS,
    output: OutputShape::Obj(&[Field::req("verdicts", OutputShape::Any)]),
    profiles: &Profile::ALL,
    examples: &[Example {
        args: r#"{"claims":[]}"#,
        golden: "tests/golden/batch/test_fact_check.json",
    }],
    ..ToolSpec::base("fact_check", test_fact_check)
};

fn test_fact_check(_: &mut Session, args: &Args, _: &mut Ctx) -> Result<Payload, ToolError> {
    let claims = args
        .get("claims")
        .and_then(Value::as_array)
        .unwrap_or_default();
    let verdicts = claims
        .iter()
        .map(|claim| {
            let args: Vec<&str> = claim
                .get("args")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .collect();
            let rel = claim.get("rel").and_then(Value::as_str);
            let verdict = if rel == Some("calls") && args == TRUE_CALL {
                "supported"
            } else {
                "refuted"
            };
            Value::object([("claim", claim.clone()), ("verdict", Value::from(verdict))])
        })
        .collect();
    let mut out = Object::new();
    out.push("verdicts", Value::Array(verdicts));
    Ok(Payload::Object(out))
}

/// Gives `tools` with `tool` before the first tool named `before`, or at the end.
fn insert(
    tools: &mut Vec<&'static ToolSpec<Session>>,
    tool: &'static ToolSpec<Session>,
    before: &str,
) {
    let at = tools
        .iter()
        .position(|t| t.name == before)
        .unwrap_or(tools.len());
    tools.insert(at, tool);
}

/// Gives the full registry: the shipped tools with `batch_run` at its catalog place.
///
/// The registry-wide tests run over it. After the register commit of WP-25, it is the
/// shipped registry.
pub fn full_registry() -> Registry<Session> {
    static CELL: OnceLock<Registry<Session>> = OnceLock::new();
    *CELL.get_or_init(|| {
        let base = shipped();
        if base.get("batch_run").is_some() {
            return base;
        }
        let mut tools: Vec<&'static ToolSpec<Session>> = base.tools().to_vec();
        insert(&mut tools, &handlers::batch_run::SPEC, "func_similar");
        Registry::new(Box::leak(tools.into_boxed_slice()))
    })
}

/// Gives the registry of the sessions: the full registry, and the test `fact_check` when the
/// full registry has no `fact_check`.
pub fn registry() -> Registry<Session> {
    static CELL: OnceLock<Registry<Session>> = OnceLock::new();
    *CELL.get_or_init(|| {
        let base = full_registry();
        if base.get("fact_check").is_some() {
            return base;
        }
        let mut tools: Vec<&'static ToolSpec<Session>> = base.tools().to_vec();
        insert(&mut tools, &TEST_FACT_CHECK, "type_get");
        Registry::new(Box::leak(tools.into_boxed_slice()))
    })
}

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives the settings of a session with the workspace root as its one root.
pub fn config() -> SessionConfig {
    SessionConfig::new(Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid"))
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

/// Runs one batch with the JSON text `args` and gives the envelope JSON.
pub fn batch(session: &mut Session, args: &str) -> Value {
    call(session, "batch_run", args)
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

/// Makes sure that the envelope is a success and gives its data.
pub fn data(envelope: &Value) -> &Value {
    assert_eq!(
        envelope.get("ok"),
        Some(&Value::Bool(true)),
        "the call fails: {envelope}"
    );
    envelope.get("data").expect("a success has data")
}

/// Gives the step entries of a batch result.
pub fn steps(envelope: &Value) -> Vec<Value> {
    data(envelope)
        .get("steps")
        .and_then(Value::as_array)
        .map(<[Value]>::to_vec)
        .unwrap_or_default()
}

/// Gives the error code of the step entry `i` of a batch result, or an empty text.
pub fn step_code(envelope: &Value, i: usize) -> String {
    steps(envelope)
        .get(i)
        .map(|s| text_at(s, "/error/code"))
        .unwrap_or_default()
}

/// Gives the first `next` call of an envelope: its tool and its arguments.
pub fn next0(envelope: &Value) -> (String, Value) {
    let call = envelope
        .pointer("/next/0")
        .unwrap_or_else(|| panic!("the envelope has no next call: {envelope}"));
    (
        text_at(call, "/tool"),
        call.get("args").cloned().unwrap_or_default(),
    )
}

/// Gives the binary ID of the demo binary.
pub fn demo_id() -> BinaryId {
    BinaryId::parse(DEMO_ID).expect("the ID parses")
}

/// One analyzed demo binary.
pub struct Analyzed {
    /// The program after the load.
    pub program: Program,
    /// The file name.
    pub file_name: String,
    /// The analysis state after the load.
    pub analysis: Option<AnalysisInfo>,
}

/// Gives the analyzed demo binary. Each test binary loads it once.
pub fn analyzed() -> &'static Analyzed {
    cached("batch-demo", || {
        let mut session = session();
        let envelope = call(&mut session, "binary_load", r#"{"builtin":"demo"}"#);
        assert_eq!(text_at(&envelope, "/data/binary_id"), DEMO_ID, "{envelope}");
        let binary = session.binary(demo_id()).expect("the demo is open");
        Analyzed {
            program: binary.program.clone(),
            file_name: binary.file_name.clone(),
            analysis: binary.analysis,
        }
    })
}

/// Makes a session of `config` with the analyzed demo binary open.
pub fn demo_with(config: SessionConfig) -> Session {
    let found = analyzed();
    let mut session = session_with(config);
    let label = session.new_label();
    session.open(OpenBinary {
        id: demo_id(),
        program: found.program.clone(),
        file_name: found.file_name.clone(),
        read_only: false,
        label,
        analysis: found.analysis,
    });
    session
}

/// Makes a session with the analyzed demo binary open.
pub fn demo() -> Session {
    demo_with(config())
}

/// Makes a session in the profile `profile` with the analyzed demo binary open.
pub fn demo_in(profile: Profile) -> Session {
    let mut config = config();
    config.profile = ProfileSet::new(profile, None);
    demo_with(config)
}

/// Gives the program of the demo binary of `session`.
pub fn program(session: &Session) -> &Program {
    &session.binary(demo_id()).expect("the demo is open").program
}

/// Gives the rev of the demo binary of `session`.
pub fn rev(session: &Session) -> u64 {
    program(session).rev().0
}

/// Gives the state hash of the demo binary of `session` as text.
pub fn state_hash(session: &Session) -> String {
    program(session)
        .state_hash()
        .expect("the state hash exists")
        .to_string()
}

/// Gives the number of journal lines of the demo binary of `session`.
pub fn lines(session: &Session) -> usize {
    session.history(demo_id()).map_or(0, |h| h.lines().len())
}

/// Gives the size of a value in characters.
pub fn chars(value: &Value) -> u64 {
    u64::try_from(ghidorah_json::write(value).chars().count()).unwrap_or(u64::MAX)
}
