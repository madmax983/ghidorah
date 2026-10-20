//! The reader, worker and writer threads of `ghidorah mcp` (ADR-0003).
//!
//! | Channel | From | To | Items |
//! |---|---|---|---|
//! | work | reader | worker | requests and the error replies of the reader, in input order, then a stop item at the end of stdin. The queue holds at most [`QUEUE`] items. |
//! | out | worker, reader | writer | reply and notification lines. The reader sends only the replies that do not fit in the work queue. |
//!
//! The reader never waits for room in the work queue, so it reads each cancel notification
//! at once (AC-172). A request that finds the queue full gets a -32603 reply ([`QUEUE_FULL`])
//! through the out channel at once, and the reader removes its cancel registration.
//!
//! The worker opens the backend, so the backend needs no `Send`. A broken pipe on stdout
//! stops the worker: the running request gets its cancel flag, and the worker takes no next
//! request. The server waits at most [`STOP_WAIT`] for the worker, so the drop of the backend
//! writes the snapshots and releases the project locks. Then the server ends with
//! [`Exit::Ok`]. The reader thread stops with the process.

use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use ghidorah_json::Value;

use super::ServeOptions;
use super::cancel::CancelMap;
use super::frame::{Frame, LineReader, MAX_LINE};
use super::rpc::{self, Message, Request, RequestId};
use super::server::{Server, is_blank, too_long};
use crate::backend::{Backend, OpenError, Options};
use crate::exit::Exit;
use crate::out::{self, Stop};
use crate::record::Recorder;
use crate::{Streams, VERSION, WORKER_STACK, catalog};

#[cfg(test)]
mod tests;

/// The method of a cancel notification.
const CANCELLED: &str = "notifications/cancelled";

/// The longest wait for the worker after stdout fails.
pub const STOP_WAIT: Duration = Duration::from_secs(5);

/// The most work items that wait for the worker. A full queue refuses the next request, so a
/// flood of large lines cannot grow the memory without a limit.
pub const QUEUE: usize = 64;

/// The message of the -32603 reply to a request that finds the work queue full.
pub const QUEUE_FULL: &str = "The work queue is full. Send the request again later.";

/// Makes the work queue: a channel that holds at most `size` items. The server uses
/// [`QUEUE`].
fn work_queue(size: usize) -> (SyncSender<Work>, Receiver<Work>) {
    mpsc::sync_channel(size)
}

/// One item of the work queue.
enum Work {
    /// A request and its cancel flag.
    Request(Request, Arc<AtomicBool>),
    /// A ready error reply of the reader.
    Reply(String),
    /// The end of the work: stdin ended, or stdout failed. The worker stops at this item, so
    /// a second sender of the queue does not keep the worker alive.
    Stop,
}

/// The state that the worker and the stop share.
#[derive(Default)]
struct RunState {
    /// `true` after a stop: the worker takes no next item.
    stopped: bool,
    /// The cancel flag of the request that the worker runs.
    flag: Option<Arc<AtomicBool>>,
}

/// The request that the worker runs, and the stop mark of a failed stdout.
#[derive(Clone, Default)]
struct Running(Arc<Mutex<RunState>>);

impl Running {
    fn state(&self) -> std::sync::MutexGuard<'_, RunState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes the start of a request with the cancel flag `flag`. Gives `false` after a stop.
    fn start(&self, flag: &Arc<AtomicBool>) -> bool {
        let mut state = self.state();
        if state.stopped {
            return false;
        }
        state.flag = Some(Arc::clone(flag));
        true
    }

    /// Notes the end of the running request.
    fn end(&self) {
        self.state().flag = None;
    }

    /// Tells if a stop came.
    fn stopped(&self) -> bool {
        self.state().stopped
    }

    /// Stops the worker: the running request gets its cancel flag, and the worker takes no
    /// next item.
    fn stop(&self) {
        let mut state = self.state();
        state.stopped = true;
        if let Some(flag) = state.flag.take() {
            flag.store(true, Ordering::Relaxed);
        }
    }
}

/// The shared log stream.
#[derive(Clone)]
struct Log(Arc<Mutex<Box<dyn Write + Send>>>);

impl Log {
    fn line(&self, text: &str) {
        let mut err = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        out::log(&mut **err, text);
    }
}

/// The out channel of the reader. The worker closes it at its end, also after a fault. So the
/// writer does not wait for the end of stdin after the worker stops.
#[derive(Clone)]
struct ReaderOut(Arc<Mutex<Option<Sender<String>>>>);

impl ReaderOut {
    fn new(out: Sender<String>) -> Self {
        Self(Arc::new(Mutex::new(Some(out))))
    }

    /// Sends `line` to the writer. Gives `false` after the end of the worker or the writer.
    fn send(&self, line: String) -> bool {
        let out = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        out.as_ref().is_some_and(|out| out.send(line).is_ok())
    }

    /// Drops the sender of the reader.
    fn close(&self) {
        let sender = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        drop(sender);
    }
}

/// Closes the out channel of the reader when the worker thread ends.
struct CloseOnDrop(ReaderOut);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// How the writer thread ends.
enum WriterEnd {
    /// The out channel closed.
    Done,
    /// stdout failed.
    Stopped(Stop),
}

/// The channels and the shared state of the reader.
struct Inlet<'a> {
    work: &'a SyncSender<Work>,
    out: &'a ReaderOut,
    cancels: &'a CancelMap,
    log: &'a Log,
}

/// Puts `item` in the work queue with no wait. When the queue is full, a request gets the
/// [`QUEUE_FULL`] reply, and an error reply goes to the writer at once. Only a stop item waits
/// for room. Gives `false` after the end of the worker or the writer.
fn enqueue(item: Work, inlet: &Inlet<'_>) -> bool {
    let line = match inlet.work.try_send(item) {
        Ok(()) => return true,
        Err(TrySendError::Disconnected(_)) => return false,
        Err(TrySendError::Full(stop @ Work::Stop)) => return inlet.work.send(stop).is_ok(),
        Err(TrySendError::Full(Work::Reply(line))) => line,
        Err(TrySendError::Full(Work::Request(request, flag))) => {
            // Only the map and `flag` hold a new flag. A flag with more holders is also the
            // flag of a request in flight with the same ID, so its registration stays.
            if Arc::strong_count(&flag) == 2 {
                inlet.cancels.finish(&request.id);
            }
            let reply = rpc::error(Some(&request.id), rpc::INTERNAL_ERROR, QUEUE_FULL, None);
            ghidorah_json::write(&reply)
        }
    };
    inlet.out.send(line)
}

/// Reads stdin lines and sends the work items in input order. Before the end of stdin, the
/// reader never waits for room in the work queue.
fn read(stdin: Box<dyn BufRead + Send>, inlet: &Inlet<'_>) {
    let Inlet { cancels, log, .. } = *inlet;
    let mut reader = LineReader::new(stdin, MAX_LINE);
    loop {
        let frame = match reader.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                log.line(&format!(
                    "The server cannot read stdin: {error}. The server stops."
                ));
                break;
            }
        };
        let item = match frame {
            Frame::TooLong { bytes } => Some(Work::Reply(ghidorah_json::write(&too_long(bytes)))),
            Frame::Line(bytes) if is_blank(&bytes) => None,
            Frame::Line(bytes) => match rpc::classify(&bytes) {
                Err(reply) => Some(Work::Reply(ghidorah_json::write(&reply))),
                Ok(Message::Request(request)) => {
                    let flag = cancels.register(&request.id);
                    Some(Work::Request(request, flag))
                }
                Ok(Message::Notification { method, params }) => {
                    let id = params
                        .as_ref()
                        .and_then(|p| p.get("requestId"))
                        .and_then(RequestId::of);
                    if let (CANCELLED, Some(id)) = (method.as_str(), id) {
                        let _ = cancels.cancel(&id);
                    }
                    None
                }
                Ok(Message::Reply) => None,
            },
        };
        if let Some(item) = item
            && !enqueue(item, inlet)
        {
            return;
        }
    }
    // The worker answers the items before this one, then it stops. No line comes after the
    // end of stdin, so the stop item can wait for room.
    let _ = enqueue(Work::Stop, inlet);
}

/// The channels and the shared state of the worker.
struct Lanes<'a> {
    items: &'a Receiver<Work>,
    out: &'a Sender<String>,
    cancels: &'a CancelMap,
    running: &'a Running,
    log: &'a Log,
}

/// Answers the work items in order until the work channel closes or a stop comes.
fn work<B: Backend>(server: &mut Server<B>, lanes: &Lanes<'_>) {
    let Lanes {
        items,
        out,
        cancels,
        running,
        log,
    } = *lanes;
    let notes = out.clone();
    let emit = move |message: Value| {
        let _ = notes.send(ghidorah_json::write(&message));
    };
    for item in items {
        if running.stopped() {
            return;
        }
        let line = match item {
            Work::Stop => return,
            Work::Reply(line) => Some(line),
            Work::Request(request, flag) => {
                if !running.start(&flag) {
                    return;
                }
                let reply = server.handle(&request, &flag, &emit);
                running.end();
                cancels.finish(&request.id);
                if let Some(error) = server.take_record_error() {
                    log.line(&format!("The call record stops: {error}."));
                }
                reply.map(|r| ghidorah_json::write(&r))
            }
        };
        if let Some(line) = line
            && out.send(line).is_err()
        {
            return;
        }
    }
}

/// Writes each line to stdout until the out channel closes or stdout fails.
fn write(mut stdout: Box<dyn Write + Send>, lines: &Receiver<String>) -> WriterEnd {
    for line in lines {
        if let Err(stop) = out::line(&mut *stdout, &line) {
            return WriterEnd::Stopped(stop);
        }
    }
    WriterEnd::Done
}

/// The channels of the worker thread.
struct WorkerChannels {
    /// The work queue.
    items: Receiver<Work>,
    /// The out channel of the worker.
    out: Sender<String>,
    /// The result of the backend open.
    ready: Sender<Result<usize, OpenError>>,
    /// The out channel of the reader. The end of the worker thread closes it.
    reader_out: ReaderOut,
}

/// Opens the backend on the worker thread, reports the result, then answers the work items.
fn start_worker<B: Backend>(
    options: Options,
    content: ghidorah_tools::ContentMode,
    recorder: Option<Recorder>,
    channels: WorkerChannels,
    cancels: CancelMap,
    running: Running,
    log: Log,
) -> io::Result<thread::JoinHandle<()>> {
    let WorkerChannels {
        items,
        out,
        ready,
        reader_out,
    } = channels;
    thread::Builder::new()
        .name("ghidorah-worker".to_owned())
        .stack_size(WORKER_STACK)
        .spawn(move || {
            // The out channel closes when the worker and the reader both drop their senders.
            let _close = CloseOnDrop(reader_out);
            let backend = match B::open(&options) {
                Ok(backend) => backend,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            let _ = ready.send(Ok(catalog::names(&backend).len()));
            let mut server = Server::new(backend, content, options.run.clock());
            if let Some(recorder) = recorder {
                server = server.with_recorder(recorder);
            }
            let lanes = Lanes {
                items: &items,
                out: &out,
                cancels: &cancels,
                running: &running,
                log: &log,
            };
            work(&mut server, &lanes);
            // The drop of the server drops the backend: snapshots, then the lock release.
            drop(server);
        })
}

/// Waits at most `wait` for `worker`. Gives `true` when the worker ends in time.
fn join_bounded(worker: thread::JoinHandle<()>, wait: Duration) -> bool {
    let Some(end) = Instant::now().checked_add(wait) else {
        return worker.join().is_ok();
    };
    while !worker.is_finished() {
        if Instant::now() >= end {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
    worker.join().is_ok()
}

/// Stops the worker after stdout fails, and waits for it at most [`STOP_WAIT`].
///
/// `stop` is a sender of the work queue. Its stop item wakes a worker that waits for work. A
/// full queue takes no stop item, but then the worker is busy, and it sees the stop mark
/// before its next item.
fn stop_worker(
    worker: thread::JoinHandle<()>,
    running: &Running,
    stop: SyncSender<Work>,
    log: &Log,
) {
    running.stop();
    let _ = stop.try_send(Work::Stop);
    drop(stop);
    if !join_bounded(worker, STOP_WAIT) {
        log.line("The worker does not stop in 5 s. The server stops without it.");
    }
}

/// Serves MCP on `streams` until stdin ends or stdout breaks.
#[must_use]
pub fn serve<B: Backend>(options: Options, serve: &ServeOptions, streams: Streams) -> Exit {
    let Streams {
        stdin,
        stdout,
        stderr,
    } = streams;
    let log = Log(Arc::new(Mutex::new(stderr)));
    let recorder = match serve.record.as_deref().map(Recorder::open).transpose() {
        Ok(recorder) => recorder,
        Err(error) => {
            log.line(&format!(
                "The record file does not open: {error}. Check the --record path."
            ));
            return Exit::Usage;
        }
    };
    let (work_tx, work_rx) = work_queue(QUEUE);
    let (out_tx, out_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let reader_out = ReaderOut::new(out_tx.clone());
    let cancels = CancelMap::new();
    let running = Running::default();
    let stop_tx = work_tx.clone();
    let channels = WorkerChannels {
        items: work_rx,
        out: out_tx,
        ready: ready_tx,
        reader_out: reader_out.clone(),
    };
    let Ok(worker) = start_worker::<B>(
        options,
        serve.content,
        recorder,
        channels,
        cancels.clone(),
        running.clone(),
        log.clone(),
    ) else {
        log.line("The worker thread does not start. The server stops.");
        return Exit::Usage;
    };
    match ready_rx.recv() {
        Ok(Ok(tools)) => log.line(&format!(
            "The MCP server {VERSION} serves {tools} tools on stdio."
        )),
        Ok(Err(error)) => {
            log.line(&error.message);
            let _ = worker.join();
            return Exit::Usage;
        }
        Err(_) => {
            log.line("The backend does not open. The server stops.");
            return Exit::Usage;
        }
    }
    let reader_log = log.clone();
    let reader = thread::Builder::new()
        .name("ghidorah-reader".to_owned())
        .spawn(move || {
            let inlet = Inlet {
                work: &work_tx,
                out: &reader_out,
                cancels: &cancels,
                log: &reader_log,
            };
            read(stdin, &inlet);
        });
    let writer = thread::Builder::new()
        .name("ghidorah-writer".to_owned())
        .spawn(move || write(stdout, &out_rx));
    let (Ok(reader), Ok(writer)) = (reader, writer) else {
        log.line("A server thread does not start. The server stops.");
        return Exit::Usage;
    };
    match writer.join() {
        Ok(WriterEnd::Done) => drop(stop_tx),
        Ok(WriterEnd::Stopped(Stop::BrokenPipe)) => {
            stop_worker(worker, &running, stop_tx, &log);
            return Exit::Ok;
        }
        Ok(WriterEnd::Stopped(Stop::Io(error))) => {
            log.line(&format!(
                "The server cannot write stdout: {error}. The server stops."
            ));
            stop_worker(worker, &running, stop_tx, &log);
            return Exit::Usage;
        }
        Err(_) => {
            stop_worker(worker, &running, stop_tx, &log);
            return Exit::Usage;
        }
    }
    if worker.join().is_err() {
        log.line("The worker thread stops after a fault. The server stops.");
        return Exit::Usage;
    }
    let _ = reader.join();
    log.line("stdin is closed. The server stops.");
    Exit::Ok
}
