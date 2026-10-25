//! Shared helpers of the claim tests: the test registry, sessions, fixtures and JSON walks.

use std::path::PathBuf;

use ghidorah_base::{Address, BinaryId, FixedClock, JumpTableId};
use ghidorah_db::{CodeUnit, FlowKind, FlowOverride, Program};
use ghidorah_json::{Limits, Value};
use ghidorah_tools::registry::shipped;
use ghidorah_tools::{Registry, Request, Roots, Session, SessionConfig, dispatch_with, handlers};

/// Gives the registry of the tests: the shipped registry, which holds `fact_check` at its
/// catalog place.
pub fn registry() -> Registry<Session> {
    shipped()
}

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Makes a session of the test registry with the analysis engine and no open binary.
pub fn session() -> Session {
    let roots = Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid");
    let mut session = Session::with_registry(
        registry(),
        SessionConfig::new(roots),
        Box::new(FixedClock::new(0)),
    );
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

/// Makes sure that the envelope is a success and gives its data.
pub fn data(envelope: &Value) -> &Value {
    assert_eq!(
        envelope.get("ok"),
        Some(&Value::Bool(true)),
        "the call fails: {envelope}"
    );
    envelope.get("data").expect("a success has data")
}

/// Gives the texts of the array at `pointer`, or an empty list.
pub fn texts(value: &Value, pointer: &str) -> Vec<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Opens a fixture: `demo` for the built-in binary, else a path under the root. Gives the
/// session and the binary ID.
pub fn open(fixture: &str) -> (Session, BinaryId) {
    let mut s = session();
    let args = if fixture == "demo" {
        Value::object([("builtin", Value::from("demo"))])
    } else {
        Value::object([("path", Value::from(fixture))])
    };
    let envelope = call_value(&mut s, "binary_load", args);
    let id = text_at(data(&envelope), "/binary_id");
    let id = BinaryId::parse(&id).expect("the load gives a binary ID");
    (s, id)
}

/// Gives the program of the binary `id` of `session`.
pub fn program(session: &Session, id: BinaryId) -> &Program {
    &session.binary(id).expect("the binary is open").program
}

/// Gives the verdicts of `claims`: one `fact_check` call per 20 claims.
pub fn verdicts(session: &mut Session, claims: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    for chunk in claims.chunks(20) {
        let args = Value::object([("claims", Value::Array(chunk.to_vec()))]);
        let envelope = call_value(session, "fact_check", args);
        let list = data(&envelope)
            .get("verdicts")
            .and_then(Value::as_array)
            .map(<[Value]>::to_vec)
            .unwrap_or_default();
        assert_eq!(list.len(), chunk.len(), "one verdict per claim: {envelope}");
        out.extend(list);
    }
    out
}

/// Makes a claim of the relation `rel` with the arguments `args`.
pub fn claim(rel: &str, args: &[Value]) -> Value {
    Value::object([
        ("rel", Value::from(rel)),
        ("args", Value::Array(args.to_vec())),
    ])
}

/// Gives the verdict of one claim.
pub fn verdict_of(session: &mut Session, rel: &str, args: &[&str]) -> Value {
    let args: Vec<Value> = args.iter().map(|a| Value::from(*a)).collect();
    verdicts(session, &[claim(rel, &args)])
        .pop()
        .expect("one verdict")
}

/// Tells if the instruction at `at` is an indirect call or jump with no target. Such a site has
/// no flow reference, no resolved jump table and no `IndirectTargets` override.
pub fn is_open_site(p: &Program, at: u64) -> bool {
    let Some(CodeUnit::Insn { flow, .. }) = p.code_unit(at) else {
        return false;
    };
    if !matches!(flow, FlowKind::ICall | FlowKind::IJmp) {
        return false;
    }
    let site = Address::ram(at);
    let flows = p.refs_from(site).iter().any(|r| r.value.key.kind.is_flow());
    let override_set = p
        .flow_override(site)
        .is_some_and(|o| matches!(o.value, FlowOverride::IndirectTargets(_)));
    let table = p
        .jump_table(JumpTableId(site))
        .is_some_and(|t| t.value.resolved && !t.value.targets.is_empty());
    !flows && !override_set && !table
}

/// Gives the open sites of each function in entry order: `(fn ID, sites)`.
pub fn open_sites(p: &Program) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for view in p.funcs() {
        let mut sites = Vec::new();
        for layer in p.layers() {
            for r in view.func.body.ranges() {
                for (at, _) in layer.listing().units_in(*r) {
                    if is_open_site(p, at) {
                        sites.push(Address::ram(at).to_string());
                    }
                }
            }
        }
        sites.sort();
        sites.dedup();
        if !sites.is_empty() {
            out.push((view.id().to_string(), sites));
        }
    }
    out
}
