//! The session: labels, the clock, sets, crashes and the demo binary.

use ghidorah_base::{BinaryId, Fuel, NoteId, SetName};
use ghidorah_db::{Edit, Note, NoteKind, NoteSet, NoteStatus, SessionLabel, SetMembers, Source};
use ghidorah_json::Value;
use ghidorah_tools::dispatch::Crash;
use ghidorah_tools::session::{LabelRule, RunConfig, Until};
use ghidorah_tools::{Frame, Host, Request, Session, demo, dispatch_with};

use crate::support::{
    DEMO_ID, call, code, config, demo as demo_session, json, root, session, session_with, text_at,
};

#[test]
fn session_labels() {
    let mut s = demo_session();
    let envelope = call(&mut s, "calc", r#"{"expr":"0x1"}"#);
    assert_eq!(text_at(&envelope, "/session"), "cli");
    assert_eq!(text_at(&envelope, "/binary_id"), DEMO_ID);
    let envelope = call(&mut s, "calc", r#"{"expr":"0x1","session":"agent-7"}"#);
    assert_eq!(text_at(&envelope, "/session"), "agent-7");
    let mut request = Request::new("calc", json(r#"{"expr":"0x1"}"#));
    request.session = Some("mcp-9".to_owned());
    let registry = s.active_registry();
    let envelope = dispatch_with(&registry, &mut s, &request).to_json();
    assert_eq!(text_at(&envelope, "/session"), "mcp-9");
    let envelope = call(&mut s, "tool_search", r#"{"name":"calc"}"#);
    assert_eq!(text_at(&envelope, "/session"), "cli");
    assert!(
        envelope.get("binary_id").is_none(),
        "tool_search binds no binary"
    );

    let mut c = config();
    c.labels = LabelRule::Mcp;
    let mut s = session_with(c);
    let envelope = call(&mut s, "tool_search", r#"{"name":"calc"}"#);
    assert_eq!(text_at(&envelope, "/session"), "mcp-1");
    let _ = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    let envelope = call(&mut s, "calc", r#"{"expr":"0x1"}"#);
    assert_eq!(text_at(&envelope, "/session"), "mcp-1");
    assert_eq!(LabelRule::Mcp.label(0), "mcp-1");
    assert_eq!(LabelRule::Mcp.label(2), "mcp-3");
    assert_eq!(LabelRule::Fixed("cli".to_owned()).label(5), "cli");
}

#[test]
fn session_clock_and_config() {
    let mut c = config();
    c.run = RunConfig {
        fixed_time: Some(1_234),
        eval_mode: true,
    };
    let clock = Box::new(ghidorah_base::ManualClock::new(99));
    let s = Session::with_registry(crate::support::registry(), c, clock);
    assert_eq!(s.clock().unix_ms(), 1_234, "fixed_time pins the clock");
    assert!(s.config().run.eval_mode);
    let s = Session::with_registry(
        crate::support::registry(),
        config(),
        Box::new(ghidorah_base::ManualClock::new(99)),
    );
    assert_eq!(s.clock().unix_ms(), 99);
    let shipped = Session::new(config(), Box::new(ghidorah_base::FixedClock::new(0)));
    assert_eq!(
        shipped.active_registry().names(),
        <Session as Host>::registry().names()
    );
    let mut s = session();
    let mut fuel = Fuel::new(10);
    let id = BinaryId::parse(DEMO_ID).expect("an ID");
    assert_eq!(
        s.analyze(id, Until::Full, &mut fuel).ok(),
        Some(None),
        "no engine"
    );
    assert!(format!("{s:?}").contains("Session"));
}

#[test]
fn demo_is_the_fixture_copy() {
    let manifest =
        std::fs::read_to_string(root().join("fixtures/manifest.json")).expect("the manifest");
    let manifest = json(&manifest);
    let entry = manifest
        .get("fixtures")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .find(|f| f.get("name").and_then(Value::as_str) == Some(demo::FIXTURE))
        .cloned()
        .expect("the fixture is in the manifest");
    let sha = ghidorah_base::hex::encode(&ghidorah_base::sha256(demo::BYTES));
    assert_eq!(
        entry.get("sha256").and_then(Value::as_str),
        Some(sha.as_str())
    );
    let fixture =
        std::fs::read(root().join("fixtures/bin").join(demo::FIXTURE)).expect("the fixture");
    assert_eq!(fixture, demo::BYTES);
    assert_eq!(
        demo::builtin("demo").map(|(name, _)| name),
        Some(demo::FILE_NAME)
    );
    assert_eq!(
        demo::builtin("demo").map(|(_, b)| b.len()),
        Some(demo::BYTES.len())
    );
    assert!(demo::builtin("other").is_none());
}

#[test]
fn session_sets_and_crashes() {
    let mut s = demo_session();
    let id = BinaryId::parse(DEMO_ID).expect("an ID");
    let binary = s.binary_mut(id).expect("the demo is open");
    let label = SessionLabel::new("test").expect("a label");
    let mut tx = binary
        .program
        .begin("note_write", Source::Agent, label.clone())
        .expect("a transaction");
    let note = Note {
        id: NoteId(1),
        kind: NoteKind::Set,
        text: String::new(),
        at: None,
        func: None,
        status: NoteStatus::Open,
        tags: Vec::new(),
        evidence: Vec::new(),
        claims: Vec::new(),
        set: Some(NoteSet {
            name: SetName::new("parsers").expect("a set name"),
            members: SetMembers::ids(vec!["fn:0x1080".to_owned()]),
        }),
        src: Source::Agent,
        session: label,
        rev: tx.pending_rev(),
    };
    tx.apply(Edit::WriteNote(Box::new(note)))
        .expect("the note applies");
    tx.commit().expect("the commit works");
    let frame = Frame {
        binary_id: Some(DEMO_ID.to_owned()),
        ..Frame::default()
    };
    let members = s.members(&frame, "set:parsers").expect("the set exists");
    assert!(members.ids.contains("fn:0x1080"));
    assert!(members.ranges.is_empty());
    let missing = s.members(&frame, "set:parser").expect_err("no such set");
    assert_eq!(missing.code, ghidorah_base::ErrorCode::NotFound);
    assert_eq!(
        missing.candidates.first().and_then(|c| c.value.as_str()),
        Some("set:parsers")
    );
    assert!(s.members(&Frame::default(), "set:parsers").is_err());

    for i in 0..ghidorah_tools::session::MAX_CRASHES + 3 {
        s.on_panic(&Crash {
            id: format!("{i:016x}"),
            tool: "calc".to_owned(),
            args: "{}".to_owned(),
            panic: "boom".to_owned(),
        });
    }
    assert_eq!(s.crashes().len(), ghidorah_tools::session::MAX_CRASHES);
    assert_eq!(
        s.crashes().last().map(|c| c.id.clone()),
        Some(format!("{:016x}", ghidorah_tools::session::MAX_CRASHES + 2))
    );
    let envelope = call(&mut s, "calc", r#"{"expr":"main"}"#);
    assert_eq!(code(&envelope), "", "the session works after the records");
    assert_eq!(s.binary(id).map(|b| b.program.notes().len()), Some(1));
    assert!(s.binary(id).is_some_and(|b| b.label == "cli"));
}
