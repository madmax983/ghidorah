use std::path::PathBuf;

use ghidorah_base::ErrorCode;
use ghidorah_json::{Object, Value};
use ghidorah_tools::dispatch::{Crash, CursorCall};
use ghidorah_tools::{
    ArgKind, Args, BinaryArg, Ctx, Frame, Globals, Host, KeyPart, Payload, SortKey, ToolError,
    ToolSpec,
};

use super::{Bare, INSTRUCTIONS};
use crate::backend::{Backend, Options};
use crate::config::Env;

#[expect(
    clippy::unnecessary_wraps,
    reason = "a test handler has the handler type, which returns a Result"
)]
fn handler(_host: &mut Bare, _args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    Ok(Payload::Object(Object::new()))
}

const BOUND: ToolSpec<Bare> = ToolSpec::base("bound_tool", handler);

const FREE: ToolSpec<Bare> = ToolSpec {
    binary: BinaryArg::None,
    ..ToolSpec::base("free_tool", handler)
};

fn bare() -> Bare {
    Bare::open(&Options::new(&Env::new(PathBuf::from("/w")), "cli")).expect("a bare backend opens")
}

#[test]
fn bound_tool_needs_a_binary() {
    let mut host = bare();
    let error = host
        .frame(&BOUND, &Globals::default(), None)
        .expect_err("no binary is open");
    assert_eq!(error.code, ErrorCode::NoBinaryOpen);
    let globals = Globals {
        binary_id: Some("b1".to_owned()),
        ..Globals::default()
    };
    let error = host
        .frame(&BOUND, &globals, None)
        .expect_err("the binary is not open");
    assert_eq!(error.code, ErrorCode::UnknownBinary);
}

#[test]
fn free_tool_frame_takes_the_session_label() {
    let mut host = bare();
    let frame = host
        .frame(&FREE, &Globals::default(), None)
        .expect("a frame");
    assert_eq!(frame.session, "cli");
    assert_eq!(frame.binary_id, None);
    assert_eq!(frame.rev, 0);
    let frame = host
        .frame(&FREE, &Globals::default(), Some("mcp-7"))
        .expect("a frame");
    assert_eq!(frame.session, "mcp-7");
    let globals = Globals {
        session: Some("agent-2".to_owned()),
        ..Globals::default()
    };
    let frame = host.frame(&FREE, &globals, Some("mcp-7")).expect("a frame");
    assert_eq!(frame.session, "agent-2");
}

#[test]
fn cursor_round_trip() {
    let host = bare();
    let args = Args::default();
    let frame = Frame::default();
    let call = CursorCall {
        tool_index: 3,
        tool: "free_tool",
        args: &args,
        frame: &frame,
    };
    let key = SortKey(vec![
        KeyPart::Int(0x40_1000),
        KeyPart::Text("näme.x".to_owned()),
    ]);
    let text = host.encode_cursor(&call, &key);
    assert_eq!(host.decode_cursor(&call, &text), Ok(key));
    let other = CursorCall {
        tool_index: 4,
        ..call
    };
    for (cursor, call) in [
        (text.as_str(), &other),
        ("zz", &call),
        ("3.q1", &call),
        ("3.tzz", &call),
        ("3.tff", &call),
    ] {
        let error = host
            .decode_cursor(call, cursor)
            .expect_err("the cursor is not valid");
        assert_eq!(error.code, ErrorCode::CursorInvalid, "{cursor}");
    }
}

#[test]
fn bare_has_no_sets_and_no_coercion() {
    let mut host = bare();
    let frame = Frame::default();
    let error = host
        .members(&frame, "set:x")
        .expect_err("a bare backend has no sets");
    assert_eq!(error.code, ErrorCode::NotFound);
    assert_eq!(host.coerce(&ArgKind::Bool, &Value::from("true")), None);
    assert!(!host.in_profile("binary_load") || !Bare::registry().names().is_empty());
    host.on_panic(&Crash {
        id: "0".to_owned(),
        tool: "t".to_owned(),
        args: "{}".to_owned(),
        panic: "p".to_owned(),
    });
    assert_eq!(host.instructions(), INSTRUCTIONS);
}

#[test]
fn open_with_a_project_fails() {
    let mut options = Options::new(&Env::new(PathBuf::from("/w")), "cli");
    options.open.push("3f2a9c0d11e4b7a2".to_owned());
    let error = Bare::open(&options).expect_err("a bare backend keeps no projects");
    assert!(error.message.contains("3f2a9c0d11e4b7a2"), "{error}");
}
