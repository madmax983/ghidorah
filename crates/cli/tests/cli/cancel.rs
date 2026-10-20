//! Cancellation (AC-169e) and progress notifications.

use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::time::Duration;

use ghidorah_cli::mcp::cancel::CancelMap;
use ghidorah_cli::mcp::rpc::RequestId;
use ghidorah_cli::mcp::{ServeOptions, serve};
use ghidorah_cli::{Exit, Options, Streams};
use ghidorah_json::Value;

use crate::common::registry::TestHost;
use crate::common::{SharedBuf, binary, env, json, root, tmp, wait_for};

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#;

/// A server on pipes: the test writes requests and reads replies line by line.
struct Live {
    input: std::io::PipeWriter,
    lines: mpsc::Receiver<String>,
    done: std::thread::JoinHandle<Exit>,
}

impl Live {
    fn start(name: &str) -> Self {
        let (in_read, input) = std::io::pipe().expect("a pipe");
        let (out_read, out_write) = std::io::pipe().expect("a pipe");
        let options = Options::new(&env(name), "mcp-1");
        let done = std::thread::spawn(move || {
            let streams = Streams {
                stdin: Box::new(BufReader::new(in_read)),
                stdout: Box::new(out_write),
                stderr: Box::new(SharedBuf::default()),
            };
            serve::<TestHost>(options, &ServeOptions::default(), streams)
        });
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out_read).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self { input, lines, done }
    }

    fn send(&mut self, line: &str) {
        self.input
            .write_all(line.as_bytes())
            .expect("the server reads");
        self.input.write_all(b"\n").expect("the server reads");
        self.input.flush().expect("the server reads");
    }

    fn next(&self) -> Value {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(20))
            .expect("the server writes a line");
        json(&line)
    }

    fn finish(self) -> Vec<Value> {
        drop(self.input);
        assert_eq!(self.done.join().expect("the server thread"), Exit::Ok);
        self.lines.iter().map(|line| json(&line)).collect()
    }
}

fn call(id: u64, tool: &str, args: &str, token: Option<&str>) -> String {
    let meta = token.map_or_else(String::new, |t| {
        format!(r#","_meta":{{"progressToken":"{t}"}}"#)
    });
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{args}{meta}}}}}"#
    )
}

fn cancel(id: u64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","method":"notifications/cancelled","params":{{"requestId":{id},"reason":"test"}}}}"#
    )
}

fn ping(id: u64) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#)
}

#[test]
fn ac_169e_cancelled() {
    let mut live = Live::start("cancel_live");
    live.send(INIT);
    assert_eq!(live.next().get("id"), Some(&json("1")));
    live.send(&call(2, "wait_cancel", r#"{"ms":10000}"#, Some("w2")));
    let first = live.next();
    assert_eq!(
        first.get("method").and_then(Value::as_str),
        Some("notifications/progress"),
        "the tool runs: {first}"
    );
    live.send(&cancel(2));
    live.send(&ping(3));
    let mut after = Vec::new();
    loop {
        let reply = live.next();
        let is_ping = reply.get("id") == Some(&json("3"));
        after.push(reply);
        if is_ping {
            break;
        }
    }
    let rest = live.finish();
    for reply in after.iter().chain(&rest) {
        assert_ne!(
            reply.get("id"),
            Some(&json("2")),
            "no reply for request 2: {reply}"
        );
    }
    let progress: Vec<u64> = std::iter::once(&first)
        .chain(&after)
        .filter(|m| m.get("method").and_then(Value::as_str) == Some("notifications/progress"))
        .filter_map(|m| m.pointer("/params/progress").and_then(Value::as_u64))
        .collect();
    assert_eq!(progress, [1, 2], "progress increases strictly");
}

#[test]
fn queued_cancel_gets_no_reply() {
    let mut live = Live::start("cancel_queued");
    live.send(INIT);
    assert_eq!(live.next().get("id"), Some(&json("1")));
    live.send(&call(2, "wait_cancel", r#"{"ms":10000}"#, None));
    live.send(&ping(3));
    live.send(&cancel(3));
    live.send(&cancel(2));
    live.send(&ping(4));
    assert_eq!(live.next().get("id"), Some(&json("4")));
    assert!(live.finish().is_empty());
}

#[test]
fn regress_broken_pipe_releases_lock() {
    let dir = tmp("broken_pipe");
    let projects = dir.join("projects");
    let projects_text = projects.to_string_lossy().into_owned();
    let workspace = root().to_string_lossy().into_owned();
    let mut child = binary(&[
        "mcp",
        "--project-root",
        &projects_text,
        "--root",
        &workspace,
    ])
    .spawn()
    .expect("the server starts");
    let mut input = child.stdin.take().expect("the stdin pipe");
    let mut output = BufReader::new(child.stdout.take().expect("the stdout pipe"));
    let mut send = |line: &str| {
        input.write_all(line.as_bytes()).expect("the server reads");
        input.write_all(b"\n").expect("the server reads");
        input.flush().expect("the server reads");
    };
    let mut reply = String::new();
    send(INIT);
    output.read_line(&mut reply).expect("the initialize reply");
    send(&call(
        2,
        "binary_load",
        r#"{"builtin":"demo","analysis":"none"}"#,
        None,
    ));
    reply.clear();
    output.read_line(&mut reply).expect("the load reply");
    assert!(reply.contains("\"isError\":false"), "{reply}");
    // The client closes the stdout of the server. The next reply breaks the pipe.
    drop(output);
    send(&ping(3));
    let status = wait_for(&mut child, 20);
    drop(input);
    assert_eq!(status.code(), Some(0), "a broken pipe exits with 0");
    let project = projects.join("467a43b75d95c826");
    assert!(
        project.join("project.json").is_file(),
        "the load made a project"
    );
    assert!(
        !project.join("project.lock").exists(),
        "the session releases the lock before the exit"
    );
    assert!(
        project.join("snapshot.json").is_file(),
        "the session writes the snapshot before the exit"
    );
}

#[test]
fn regress_cancelled_commit_still_replies() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use ghidorah_base::FixedClock;
    use ghidorah_cli::mcp::rpc::{self, Message};
    use ghidorah_cli::mcp::server::Server;
    use ghidorah_cli::record::Recorder;
    use ghidorah_cli::shipped::Shipped;
    use ghidorah_cli::{Backend, record};
    use ghidorah_tools::ContentMode;

    let request = |line: &str| match rpc::classify(line.as_bytes()) {
        Ok(Message::Request(r)) => r,
        other => panic!("not a request: {other:?}"),
    };
    let mut options = Options::new(&env("cancel_commit"), "mcp-1");
    options.roots = vec![root()];
    let backend = <Shipped as Backend>::open(&options).expect("the backend opens");
    let records = SharedBuf::default();
    let mut server = Server::new(backend, ContentMode::Plain, Box::new(FixedClock::new(0)))
        .with_recorder(Recorder::new(Box::new(records.clone())));
    let no = Arc::new(AtomicBool::new(false));
    assert!(server.handle(&request(INIT), &no, &|_| {}).is_some());
    // The client cancels at the first progress notification of the load.
    let flag = Arc::new(AtomicBool::new(false));
    let seen = Mutex::new(0usize);
    let emit = |_: Value| {
        flag.store(true, Ordering::Relaxed);
        *seen.lock().expect("the lock") += 1;
    };
    let load = call(
        2,
        "binary_load",
        r#"{"path":"fixtures/bin/large.gcc-O2"}"#,
        Some("p2"),
    );
    let reply = server.handle(&request(&load), &flag, &emit);
    assert!(
        *seen.lock().expect("the lock") > 0,
        "the load sends progress"
    );
    let reply = reply.expect("a cancelled load that opened a binary still replies");
    let envelope = reply.get("result").expect("a result");
    assert_eq!(envelope.get("ok"), Some(&Value::Bool(true)), "{envelope}");
    assert_eq!(
        envelope.get("noop"),
        Some(&Value::Bool(false)),
        "{envelope}"
    );
    assert_eq!(
        envelope
            .pointer("/data/analysis/state")
            .and_then(Value::as_str),
        Some("budget_stopped"),
        "the cancel stops the analysis: {envelope}"
    );
    let entries = record::parse(&records.text()).expect("the record parses");
    assert!(
        entries
            .iter()
            .any(|e| e.request.get("id") == Some(&json("2"))),
        "the recorder keeps the call: {}",
        records.text()
    );
}

#[test]
fn cancel_map_sets_and_drops_flags() {
    let map = CancelMap::new();
    let id = RequestId::Int(7);
    let flag = map.register(&id);
    assert_eq!(map.len(), 1);
    assert!(map.cancel(&id));
    assert!(flag.load(std::sync::atomic::Ordering::Relaxed));
    map.finish(&id);
    assert!(map.is_empty());
    assert!(!map.cancel(&RequestId::Str("7".to_owned())));
}
