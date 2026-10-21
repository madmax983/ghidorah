//! `analysis_run` over MCP: progress per fuel slice and cancellation (AC-172, AC-173).
//!
//! The server runs in the test process with the shipped backend. The cancel test first runs
//! the dispatcher of the server with a cancel flag that is set at the start. Then the emit
//! function sets the cancel flag at the first progress notification, as a client does.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use ghidorah_base::FixedClock;
use ghidorah_cli::mcp::rpc::{self, Message, Request};
use ghidorah_cli::mcp::server::Server;
use ghidorah_cli::shipped::Shipped;
use ghidorah_cli::{Backend, Options};
use ghidorah_json::{Object, Value};
use ghidorah_tools::ContentMode;
use ghidorah_tools::handlers::analysis_run::SLICE_STEPS;

use crate::common::{env, root};

/// The fixture of the tests: large enough for many fuel slices.
const FIXTURE: &str = "fixtures/bin/large.gcc-O2";

/// The initialize request of the tests.
const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;

/// Gives an initialized server over the shipped backend with the workspace root.
fn server(name: &str) -> Server<Shipped> {
    let mut options = Options::new(&env(name), "mcp-1");
    options.roots = vec![root()];
    let backend = <Shipped as Backend>::open(&options).expect("the backend opens");
    let mut s = Server::new(backend, ContentMode::Plain, Box::new(FixedClock::new(0)));
    let no = Arc::new(AtomicBool::new(false));
    let reply = s.handle(&request(INIT), &no, &|_| {}).expect("a reply");
    assert!(reply.get("result").is_some(), "{reply}");
    s
}

fn request(line: &str) -> Request {
    match rpc::classify(line.as_bytes()) {
        Ok(Message::Request(r)) => r,
        other => panic!("not a request: {other:?}"),
    }
}

fn call(id: u64, tool: &str, args: &str, token: Option<&str>) -> Request {
    let meta = token.map_or_else(String::new, |t| {
        format!(r#","_meta":{{"progressToken":"{t}"}}"#)
    });
    request(&format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{args}{meta}}}}}"#
    ))
}

/// Gives the data of a tool result: the plain mode sends the envelope as the result.
fn data(reply: &Value) -> Value {
    let envelope = reply.get("result").expect("a result");
    assert_eq!(envelope.get("ok"), Some(&Value::Bool(true)), "{envelope}");
    envelope.get("data").cloned().expect("data")
}

fn progress_values(lines: &[Value]) -> Vec<u64> {
    lines
        .iter()
        .filter(|m| m.get("method").and_then(Value::as_str) == Some("notifications/progress"))
        .filter_map(|m| m.pointer("/params/progress").and_then(Value::as_u64))
        .collect()
}

/// Loads the fixture with no analysis. Gives its binary ID.
fn load(server: &mut Server<Shipped>) -> String {
    let no = Arc::new(AtomicBool::new(false));
    let args = format!(r#"{{"path":"{FIXTURE}","analysis":"none"}}"#);
    let reply = server
        .handle(&call(1, "binary_load", &args, None), &no, &|_| {})
        .expect("a reply");
    let got = data(&reply);
    assert_eq!(
        got.pointer("/analysis/state").and_then(Value::as_str),
        Some("none")
    );
    got.get("binary_id")
        .and_then(Value::as_str)
        .expect("an ID")
        .to_owned()
}

#[test]
fn ac_173_progress_monotonic() {
    let mut s = server("analysis_progress");
    let _ = load(&mut s);
    let seen = Mutex::new(Vec::new());
    let emit = |v: Value| seen.lock().expect("the lock").push(v);
    let no = Arc::new(AtomicBool::new(false));
    let reply = s
        .handle(&call(2, "analysis_run", "{}", Some("p2")), &no, &emit)
        .expect("a reply");
    let got = data(&reply);
    assert_eq!(got.get("state").and_then(Value::as_str), Some("complete"));
    let used = got
        .get("steps_used")
        .and_then(Value::as_u64)
        .expect("steps");
    let values = progress_values(&seen.lock().expect("the lock"));
    assert!(values.len() >= 3, "one notification per slice: {values:?}");
    assert!(values.windows(2).all(|w| w[0] < w[1]), "{values:?}");
    assert_eq!(
        values.last(),
        Some(&used),
        "the last slice reports every unit"
    );
    // The sliced loop gives each slice `f = SLICE_STEPS.max(used / 4)` fuel, with `used` the
    // work of the call so far. A slice uses its fuel, and its last step can run past it: a
    // step that starts always ends. Two slices between two reports use at least `2 f`, so
    // the bound `< 2 f` fails a report every second slice.
    let mut before = 0;
    for (i, v) in values.iter().enumerate() {
        let fuel = SLICE_STEPS.max(before / 4);
        if i + 1 < values.len() {
            assert!(v - before >= fuel, "a slice uses its fuel: {values:?}");
        }
        assert!(
            v - before < 2 * fuel,
            "one report per slice: {before} to {v} in {values:?}"
        );
        before = *v;
    }
    // No token: no notification.
    let quiet = Mutex::new(Vec::new());
    let emit = |v: Value| quiet.lock().expect("the lock").push(v);
    let _ = s.handle(&call(3, "analysis_run", "{}", None), &no, &emit);
    assert!(quiet.lock().expect("the lock").is_empty());
}

/// Gives a shipped backend with the workspace root and the fixture loaded with no analysis.
fn backend_with_fixture(name: &str) -> Shipped {
    let mut options = Options::new(&env(name), "mcp-1");
    options.roots = vec![root()];
    let mut backend = <Shipped as Backend>::open(&options).expect("the backend opens");
    let args = format!(r#"{{"path":"{FIXTURE}","analysis":"none"}}"#);
    let load = tool_call(&mut backend, "binary_load", &args, None);
    assert_eq!(load.get("ok"), Some(&Value::Bool(true)), "{load}");
    backend
}

/// Runs one tool call on `backend` through the dispatcher of the server, with the cancel flag
/// `cancel`. Gives the envelope JSON.
fn tool_call(
    backend: &mut Shipped,
    tool: &str,
    args: &str,
    cancel: Option<&Arc<AtomicBool>>,
) -> Value {
    let args = ghidorah_json::parse(args, &ghidorah_json::Limits::DEFAULT).expect("JSON");
    let mut call = ghidorah_tools::Request::new(tool, args);
    call.cancel = cancel.cloned();
    ghidorah_tools::dispatch(backend, &call).to_json()
}

#[test]
fn ac_172_cancellation() {
    // A cancel flag that is set when the tool starts stops the run at the first fuel
    // checkpoint: the end of the first slice. The dispatcher is the one of the server, which
    // gives no reply to such a call (see the case below). The one report gives the work of
    // the slice, which equals the work of a run with the fuel of one slice.
    let mut b = backend_with_fixture("analysis_cancel_first");
    let set = Arc::new(AtomicBool::new(true));
    let (sender, reports) = mpsc::channel();
    let mut run = ghidorah_tools::Request::new("analysis_run", Value::Object(Object::new()));
    run.cancel = Some(Arc::clone(&set));
    run.progress = Some(sender);
    let envelope = ghidorah_tools::dispatch(&mut b, &run).to_json();
    drop(run);
    let values: Vec<u64> = reports.iter().map(|p| p.progress).collect();
    assert_eq!(values.len(), 1, "the run stops after one slice: {values:?}");
    assert_eq!(
        envelope.pointer("/data/steps_used").and_then(Value::as_u64),
        values.first().copied(),
        "{envelope}"
    );
    let id = envelope
        .get("binary_id")
        .and_then(Value::as_str)
        .expect("an ID");
    let after = tool_call(
        &mut b,
        "binary_load",
        &format!(r#"{{"binary_id":"{id}"}}"#),
        None,
    );
    assert_eq!(
        after
            .pointer("/data/analysis/state")
            .and_then(Value::as_str),
        Some("budget_stopped"),
        "{after}"
    );
    let mut one = backend_with_fixture("analysis_one_slice");
    let slice = tool_call(
        &mut one,
        "analysis_run",
        &format!(r#"{{"max_steps":{SLICE_STEPS}}}"#),
        None,
    );
    assert_eq!(
        slice.pointer("/data/steps_used").and_then(Value::as_u64),
        values.first().copied(),
        "the cancelled run does the work of one slice: {slice}"
    );

    // A cancel at the first report over MCP: the forwarder thread sets the flag, so the stop
    // can come a slice later. No reply follows. The run stops before its end and resumes.
    let mut s = server("analysis_cancel");
    let id = load(&mut s);
    let flag = Arc::new(AtomicBool::new(false));
    let seen = Mutex::new(Vec::new());
    let emit = |v: Value| {
        flag.store(true, Ordering::Relaxed);
        seen.lock().expect("the lock").push(v);
    };
    let reply = s.handle(&call(2, "analysis_run", "{}", Some("c2")), &flag, &emit);
    assert!(reply.is_none(), "no response follows the cancel");
    let values = progress_values(&seen.lock().expect("the lock"));
    assert!(
        !values.is_empty(),
        "the run sends progress before the cancel"
    );
    let no = Arc::new(AtomicBool::new(false));
    let args = format!(r#"{{"binary_id":"{id}"}}"#);
    let after = s
        .handle(&call(3, "binary_load", &args, None), &no, &|_| {})
        .expect("a reply");
    let got = data(&after);
    assert_eq!(
        got.pointer("/analysis/state").and_then(Value::as_str),
        Some("budget_stopped"),
        "the cancel stops the run at a fuel checkpoint: {got}"
    );
    let dry = s
        .handle(
            &call(5, "analysis_run", r#"{"dry_run":true}"#, None),
            &no,
            &|_| {},
        )
        .expect("a reply");
    assert_eq!(data(&dry).get("resume"), Some(&Value::Bool(true)));
    let done = s
        .handle(&call(4, "analysis_run", "{}", None), &no, &|_| {})
        .expect("a reply");
    assert_eq!(
        data(&done).get("state").and_then(Value::as_str),
        Some("complete"),
        "the next call resumes the run"
    );
}
