//! Shared helpers of the history tests: the test registry, sessions, projects and edits.

use std::path::PathBuf;

use ghidorah_base::{Address, BinaryId, FixedClock};
use ghidorah_db::{CommentKind, Edit, StateHash, SymKind};
use ghidorah_json::{Limits, Value};
use ghidorah_tools::session::{LabelRule, ProjectsConfig};
use ghidorah_tools::{
    Args, Ctx, Payload, Registry, Request, Roots, Session, SessionConfig, ToolError, ToolSpec,
    dispatch_with, handlers,
};

/// The binary ID of the demo binary.
pub const DEMO_ID: &str = "467a43b75d95c826";

/// The test tool that opens a transaction, applies an edit and panics.
pub const BOOM: ToolSpec<Session> = ToolSpec {
    title: "Panic in a transaction",
    summary: "Panic in a transaction: a test tool.",
    description: "Panic in a transaction: a test tool.",
    mutating: true,
    annotations: ghidorah_tools::Annotations::EDIT,
    ..ToolSpec::base("test_boom", boom)
};

fn boom(session: &mut Session, _args: &Args, ctx: &mut Ctx) -> Result<Payload, ToolError> {
    let id = session.bound(&ctx.frame)?.id;
    let binary = session.binary_mut(id).expect("the binary is open");
    let label = ghidorah_db::SessionLabel::new("mcp-1").expect("a label");
    let mut tx = binary
        .program
        .begin("test_boom", ghidorah_db::Source::Agent, label)
        .expect("a transaction");
    let fact = tx.fact("half_done".to_owned());
    tx.apply(Edit::SetName {
        addr: Address::ram(0x10a0),
        key: None,
        kind: SymKind::Label,
        primary: true,
        name: Some(fact),
        evidence: Vec::new(),
    })
    .expect("the edit applies");
    panic!("the test tool panics in a transaction");
}

/// The tools of the tests: the shipped tools, the history tools and the test tools, in the
/// `tools/list` order of design Section 10.3.
pub static TOOLS: &[&ToolSpec<Session>] = &[
    &handlers::load::SPEC,
    &handlers::calc::SPEC,
    &handlers::history_list::SPEC,
    &handlers::tool_search::SPEC,
    &handlers::history_undo::SPEC,
    &BOOM,
];

/// The registry of the shipped tools and the history tools, in catalog order.
pub static CATALOG: &[&ToolSpec<Session>] = &[
    &handlers::load::SPEC,
    &handlers::calc::SPEC,
    &handlers::history_list::SPEC,
    &handlers::tool_search::SPEC,
    &handlers::history_undo::SPEC,
];

/// Gives the workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Gives a new empty directory for one test.
pub fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("history")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp directory exists");
    dir
}

/// Gives the settings of a session with no projects root.
pub fn config() -> SessionConfig {
    let mut config =
        SessionConfig::new(Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid"));
    config.labels = LabelRule::Mcp;
    config
}

/// Gives the settings of a session with the projects root `dir`.
pub fn config_in(dir: &std::path::Path) -> SessionConfig {
    let mut config = config();
    config.projects = Some(ProjectsConfig {
        root: dir.to_path_buf(),
        named: true,
        break_lock: false,
    });
    config
}

/// Makes a session of the test registry with `config`.
pub fn session_with(config: SessionConfig) -> Session {
    Session::with_registry(Registry::new(TOOLS), config, Box::new(FixedClock::new(0)))
}

/// Parses JSON text.
pub fn json(text: &str) -> Value {
    ghidorah_json::parse(text, &Limits::DEFAULT).expect("the test JSON parses")
}

/// Runs one call and gives the envelope JSON.
pub fn call(session: &mut Session, tool: &str, args: &str) -> Value {
    let registry = session.active_registry();
    dispatch_with(&registry, session, &Request::new(tool, json(args))).to_json()
}

/// Gives the error code of an envelope, or an empty text for a success.
pub fn code(envelope: &Value) -> String {
    envelope
        .pointer("/error/code")
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

/// Gives the items of a list envelope.
pub fn items(envelope: &Value) -> Vec<Value> {
    data(envelope)
        .get("items")
        .and_then(Value::as_array)
        .expect("a list has items")
        .to_vec()
}

/// Loads the demo binary and gives its ID.
pub fn load_demo(session: &mut Session) -> BinaryId {
    let envelope = call(session, "binary_load", r#"{"builtin":"demo"}"#);
    let id = data(&envelope)
        .get("binary_id")
        .and_then(Value::as_str)
        .expect("a binary ID");
    BinaryId::parse(id).expect("the ID parses")
}

/// Commits one rename of `addr` in the session `label` and gives the new rev.
pub fn rename(session: &mut Session, id: BinaryId, label: &str, addr: u64, name: &str) -> u64 {
    let (commit, ()) = session
        .transact(id, "symbol_rename", label, |tx| {
            let fact = tx.fact(name.to_owned());
            tx.apply(Edit::SetName {
                addr: Address::ram(addr),
                key: None,
                kind: SymKind::Label,
                primary: true,
                name: Some(fact),
                evidence: vec!["fn:0x1080".to_owned()],
            })
            .map(drop)
            .map_err(|e| ToolError::new(e.code()))
        })
        .expect("the rename commits");
    commit.rev.0
}

/// Commits one comment at `addr` in the session `label` and gives the new rev.
pub fn comment(session: &mut Session, id: BinaryId, label: &str, addr: u64, text: &str) -> u64 {
    let (commit, ()) = session
        .transact(id, "comment_set", label, |tx| {
            let fact = tx.fact(text.to_owned());
            tx.apply(Edit::SetComment {
                addr: Address::ram(addr),
                kind: CommentKind::Eol,
                text: Some(fact),
            })
            .map(drop)
            .map_err(|e| ToolError::new(e.code()))
        })
        .expect("the comment commits");
    commit.rev.0
}

/// Gives the state hash and the rev of the open binary `id`.
pub fn state(session: &Session, id: BinaryId) -> (StateHash, u64) {
    let program = &session.binary(id).expect("the binary is open").program;
    (
        program.state_hash().expect("the state hash"),
        program.rev().0,
    )
}
