//! The work queue of the reader and the worker.

use std::fmt::Write as _;
use std::io::{BufRead, Cursor};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::{Log, QUEUE, read, work_queue};
use crate::mcp::cancel::CancelMap;

/// The number of requests on stdin: more than the queue holds.
const REQUESTS: usize = 200;

#[test]
fn regress_mcp_queue_is_bounded() {
    let (work, items) = work_queue();
    let cancels = CancelMap::new();
    let log = Log(Arc::new(Mutex::new(Box::new(std::io::sink()))));
    let mut text = String::new();
    for id in 1..=REQUESTS {
        let _ = writeln!(text, r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
    }
    let stdin: Box<dyn BufRead + Send> = Box::new(Cursor::new(text.into_bytes()));
    let seen = cancels.clone();
    let reader = thread::spawn(move || read(stdin, &work, &seen, &log));
    // No worker takes items. The reader stops at the end of stdin, or it waits for room.
    let end = Instant::now() + Duration::from_secs(10);
    while !reader.is_finished() && cancels.len() <= QUEUE && Instant::now() < end {
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(100));
    let registered = cancels.len();
    let finished = reader.is_finished();
    // The drop of the queue end makes the send of the reader fail, so the reader stops.
    drop(items);
    reader.join().expect("the reader thread");
    assert!(!finished, "the reader waits for room in the queue");
    assert_eq!(
        registered,
        QUEUE + 1,
        "the queue holds 64 requests, and the reader holds one more"
    );
}
