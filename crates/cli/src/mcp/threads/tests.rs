//! The work queue of the reader and the worker.

use std::fmt::Write as _;
use std::io::{self, BufRead, Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ghidorah_json::Value;

use super::{Inlet, Log, OUT, QUEUE, QUEUE_FULL, ReaderOut, Work, out_channel, read, work_queue};
use crate::mcp::cancel::CancelMap;
use crate::mcp::rpc::{INTERNAL_ERROR, INVALID_REQUEST, MAX_ID_CHARS, PARSE_ERROR, RequestId};

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

/// The reader thread, the work queue end, the out channel end and the cancel map of a test.
type Started = (
    thread::JoinHandle<()>,
    Receiver<Work>,
    Receiver<String>,
    CancelMap,
);

/// Starts the reader on `text` with a work queue of `size` items. No worker takes items.
fn start(text: String, size: usize) -> Started {
    start_on(Box::new(Cursor::new(text.into_bytes())), size)
}

/// Starts the reader on `stdin` with a work queue of `size` items. No worker takes items, and
/// the out channel holds [`OUT`] lines.
fn start_on(stdin: Box<dyn BufRead + Send>, size: usize) -> Started {
    let (work, items) = work_queue(size);
    let (out_tx, out_rx) = out_channel(OUT);
    let cancels = CancelMap::new();
    let seen = cancels.clone();
    let log = Log(Arc::new(Mutex::new(Box::new(io::sink()))));
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

/// An input that counts the bytes that the reader takes.
struct Counted {
    inner: Cursor<Vec<u8>>,
    taken: Arc<AtomicUsize>,
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let _ = self.taken.fetch_add(n, Ordering::Relaxed);
        Ok(n)
    }
}

impl BufRead for Counted {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
        let _ = self.taken.fetch_add(amount, Ordering::Relaxed);
    }
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

#[test]
fn regress_reader_replies_are_bounded() {
    // A queue of 2 takes the first two pings. Each later line gets a reply of the reader: a
    // bad line gets -32700, and a ping gets the full-queue error.
    let late = 4 * OUT;
    let mut text = pings(2);
    for n in 0..late {
        if n % 2 == 0 {
            text.push_str("x\n");
        } else {
            let _ = writeln!(
                text,
                r#"{{"jsonrpc":"2.0","id":{},"method":"ping"}}"#,
                n + 3
            );
        }
    }
    let total = text.len();
    let lines: Vec<usize> = text
        .bytes()
        .enumerate()
        .filter_map(|(i, b)| (b == b'\n').then_some(i + 1))
        .collect();
    let taken = Arc::new(AtomicUsize::new(0));
    let stdin = Counted {
        inner: Cursor::new(text.into_bytes()),
        taken: Arc::clone(&taken),
    };
    let (reader, items, out, _cancels) = start_on(Box::new(stdin), 2);
    // Nobody reads the out channel. The reader reads 2 lines for the queue, the bound of
    // lines for the out channel and one more line whose reply waits.
    let bound = lines.get(2 + OUT).copied().expect("enough lines");
    let end = Instant::now() + WAIT;
    while taken.load(Ordering::Relaxed) < bound && Instant::now() < end {
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(200));
    let read_bytes = taken.load(Ordering::Relaxed);
    let read_lines = lines.iter().filter(|&&end| end <= read_bytes).count();
    assert!(
        read_bytes < total,
        "the reader waits for the writer: it read {read_bytes} of {total} bytes"
    );
    assert!(
        read_lines <= 2 + OUT + 1,
        "at most {OUT} reader replies wait in the out channel: the reader read {read_lines} lines"
    );
    // The writer resumes. The reader then sends each later reply.
    let mut replies = Vec::new();
    while replies.len() < late {
        let line = out
            .recv_timeout(WAIT)
            .expect("the reader sends each reply when the writer reads");
        replies.push(parse(&line));
    }
    drop(items);
    reader.join().expect("the reader thread");
    for (n, reply) in replies.iter().enumerate() {
        let code = reply.pointer("/error/code").and_then(Value::as_i64);
        if n % 2 == 0 {
            assert_eq!(code, Some(PARSE_ERROR), "the reply of line {n}: {reply:?}");
        } else {
            let id = u64::try_from(n + 3).expect("a small ID");
            assert!(is_full_reply(reply, id), "the reply of line {n}: {reply:?}");
        }
    }
    assert!(out.try_recv().is_err(), "the reader sends no other line");
}

/// Gives a ping request with the string ID `id`.
fn ping_str(id: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":\"{id}\",\"method\":\"ping\"}}\n")
}

#[test]
fn regress_long_string_id_refused() {
    let longest = "k".repeat(MAX_ID_CHARS);
    let long = "q".repeat(MAX_ID_CHARS + 1);
    let mut text = ping_str(&long);
    text.push_str(&ping_str(&longest));
    let (reader, items, out, cancels) = start(text, 2);
    let first = items.recv_timeout(WAIT).expect("the reply of the long ID");
    let second = items
        .recv_timeout(WAIT)
        .expect("the request of the longest ID");
    let registered = cancels.len();
    drop(items);
    reader.join().expect("the reader thread");
    let Work::Reply(line) = first else {
        panic!("a string ID above {MAX_ID_CHARS} characters is not a request");
    };
    let reply = parse(&line);
    assert_eq!(
        reply.pointer("/error/code").and_then(Value::as_i64),
        Some(INVALID_REQUEST),
        "{reply:?}"
    );
    assert_eq!(reply.get("id"), Some(&Value::Null), "{reply:?}");
    assert!(
        !line.contains(&long),
        "the reply does not echo the ID: {line}"
    );
    let Work::Request(request, _) = second else {
        panic!("a string ID of {MAX_ID_CHARS} characters is a request");
    };
    assert_eq!(request.id, RequestId::Str(longest));
    assert_eq!(registered, 1, "only the valid request has a cancel flag");
    assert!(out.try_recv().is_err(), "the out channel holds no line");
}
