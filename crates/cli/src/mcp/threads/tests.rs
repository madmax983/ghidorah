//! The work queue of the reader and the worker.

use std::fmt::Write as _;
use std::io::{BufRead, Cursor};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ghidorah_json::Value;

use super::{Inlet, Log, QUEUE, QUEUE_FULL, ReaderOut, Work, read, work_queue};
use crate::mcp::cancel::CancelMap;
use crate::mcp::rpc::{INTERNAL_ERROR, RequestId};

/// The number of requests on stdin: more than the queue holds.
const REQUESTS: usize = 200;

/// The longest wait of a test for the reader.
const WAIT: Duration = Duration::from_secs(10);

/// Gives the text of `count` ping requests with the IDs 1 to `count`.
fn pings(count: usize) -> String {
    let mut text = String::new();
    for id in 1..=count {
        let _ = writeln!(text, r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
    }
    text
}

/// Starts the reader on `text` with a work queue of `size` items. No worker takes items.
fn start(
    text: String,
    size: usize,
) -> (
    thread::JoinHandle<()>,
    Receiver<Work>,
    Receiver<String>,
    CancelMap,
) {
    let (work, items) = work_queue(size);
    let (out_tx, out_rx) = mpsc::channel();
    let cancels = CancelMap::new();
    let seen = cancels.clone();
    let log = Log(Arc::new(Mutex::new(Box::new(std::io::sink()))));
    let stdin: Box<dyn BufRead + Send> = Box::new(Cursor::new(text.into_bytes()));
    let reader = thread::spawn(move || {
        let out = ReaderOut::new(out_tx);
        let inlet = Inlet {
            work: &work,
            out: &out,
            cancels: &seen,
            log: &log,
        };
        read(stdin, &inlet);
    });
    (reader, items, out_rx, cancels)
}

/// Gives the parsed reply line.
fn parse(line: &str) -> Value {
    ghidorah_json::parse(line, &ghidorah_json::Limits::DEFAULT).unwrap_or(Value::Null)
}

/// Tells if `reply` is the full-queue error of request `id`.
fn is_full_reply(reply: &Value, id: u64) -> bool {
    let error = reply.get("error");
    reply.get("id").and_then(Value::as_u64) == Some(id)
        && error
            .and_then(|e| e.get("code"))
            .and_then(Value::as_i64)
            .is_some_and(|code| code == INTERNAL_ERROR)
        && error
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .is_some_and(|text| text == QUEUE_FULL)
}

#[test]
fn regress_mcp_queue_is_bounded() {
    let (reader, items, out, cancels) = start(pings(REQUESTS), QUEUE);
    // The queue holds 64 requests. Each later request gets the full-queue error at once.
    let mut refused = Vec::new();
    while refused.len() < REQUESTS - QUEUE {
        let line = out
            .recv_timeout(WAIT)
            .expect("the reader refuses each request after the queue fills");
        refused.push(parse(&line));
    }
    let registered = cancels.len();
    // The drop of the queue end makes the send of the stop item fail, so the reader stops.
    drop(items);
    reader.join().expect("the reader thread");
    assert_eq!(
        registered, QUEUE,
        "only the queued requests have cancel flags"
    );
    for (reply, id) in refused.iter().zip(QUEUE + 1..) {
        let id = u64::try_from(id).expect("a small ID");
        assert!(
            is_full_reply(reply, id),
            "the reply of request {id}: {reply:?}"
        );
    }
    assert!(out.try_recv().is_err(), "the reader sends no other line");
}

#[test]
fn regress_cancel_read_while_queue_full() {
    let mut text = pings(3);
    text.push_str(
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#,
    );
    text.push('\n');
    // A queue of 2 and a blocked worker: requests 1 and 2 wait, and request 3 finds it full.
    let (reader, items, out, cancels) = start(text, 2);
    let line = out
        .recv_timeout(WAIT)
        .expect("request 3 gets a reply at once");
    let reply = parse(&line);
    assert!(
        is_full_reply(&reply, 3),
        "the reply of request 3: {reply:?}"
    );
    let first = cancels.register(&RequestId::Int(1));
    let end = Instant::now() + WAIT;
    while !first.load(Ordering::Relaxed) && Instant::now() < end {
        thread::sleep(Duration::from_millis(5));
    }
    let cancelled_before_resume = first.load(Ordering::Relaxed);
    // The worker resumes. Drop of the queue end stops a reader that still waits.
    let mut queued = Vec::new();
    while let Ok(item) = items.recv_timeout(Duration::from_millis(500)) {
        let Work::Request(request, flag) = item else {
            break;
        };
        queued.push((request.id, flag.load(Ordering::Relaxed)));
    }
    drop(items);
    reader.join().expect("the reader thread");
    assert!(
        cancelled_before_resume,
        "the reader sets the cancel flag while the queue is full"
    );
    assert_eq!(
        queued,
        [(RequestId::Int(1), true), (RequestId::Int(2), false)],
        "the queue holds requests 1 and 2, and request 1 is cancelled"
    );
    assert_eq!(
        cancels.len(),
        2,
        "the refused request 3 has no cancel registration"
    );
    assert!(out.try_recv().is_err(), "request 3 gets one reply only");
}
