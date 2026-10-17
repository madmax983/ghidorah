//! The reader, worker and writer threads of `ghidorah mcp` (ADR-0003).
//!
//! | Channel | From | To | Items |
//! |---|---|---|---|
//! | work | reader | worker | requests and the error replies of the reader, in input order |
//! | out | worker | writer | reply and notification lines |
//!
//! The worker opens the backend, so the backend needs no `Send`. A broken pipe on stdout
//! ends the server at once with [`Exit::Ok`]. The other threads then stop with the process.

use std::io::{self, BufRead, Write};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

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

/// The method of a cancel notification.
const CANCELLED: &str = "notifications/cancelled";

/// One item of the work queue.
enum Work {
    /// A request and its cancel flag.
    Request(Request, Arc<AtomicBool>),
    /// A ready error reply of the reader.
    Reply(String),
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

/// How the writer thread ends.
enum WriterEnd {
    /// The out channel closed.
    Done,
    /// stdout failed.
    Stopped(Stop),
}

/// Reads stdin lines and sends the work items in input order.
fn read(stdin: Box<dyn BufRead + Send>, work: &Sender<Work>, cancels: &CancelMap, log: &Log) {
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
            && work.send(item).is_err()
        {
            break;
        }
    }
}

/// Answers the work items in order until the work channel closes.
fn work<B: Backend>(
    server: &mut Server<B>,
    items: &Receiver<Work>,
    out: &Sender<String>,
    cancels: &CancelMap,
    log: &Log,
) {
    let notes = out.clone();
    let emit = move |message: Value| {
        let _ = notes.send(ghidorah_json::write(&message));
    };
    for item in items {
        let line = match item {
            Work::Reply(line) => Some(line),
            Work::Request(request, flag) => {
                let reply = server.handle(&request, &flag, &emit);
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

/// Opens the backend on the worker thread, reports the result, then answers the work items.
fn start_worker<B: Backend>(
    options: Options,
    content: ghidorah_tools::ContentMode,
    recorder: Option<Recorder>,
    channels: (
        Receiver<Work>,
        Sender<String>,
        Sender<Result<usize, OpenError>>,
    ),
    cancels: CancelMap,
    log: Log,
) -> io::Result<thread::JoinHandle<()>> {
    let (items, out, ready) = channels;
    thread::Builder::new()
        .name("ghidorah-worker".to_owned())
        .stack_size(WORKER_STACK)
        .spawn(move || {
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
            work(&mut server, &items, &out, &cancels, &log);
        })
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
    let (work_tx, work_rx) = mpsc::channel();
    let (out_tx, out_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let cancels = CancelMap::new();
    let channels = (work_rx, out_tx, ready_tx);
    let Ok(worker) = start_worker::<B>(
        options,
        serve.content,
        recorder,
        channels,
        cancels.clone(),
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
        .spawn(move || read(stdin, &work_tx, &cancels, &reader_log));
    let writer = thread::Builder::new()
        .name("ghidorah-writer".to_owned())
        .spawn(move || write(stdout, &out_rx));
    let (Ok(reader), Ok(writer)) = (reader, writer) else {
        log.line("A server thread does not start. The server stops.");
        return Exit::Usage;
    };
    match writer.join() {
        Ok(WriterEnd::Done) => {}
        Ok(WriterEnd::Stopped(Stop::BrokenPipe)) => return Exit::Ok,
        Ok(WriterEnd::Stopped(Stop::Io(error))) => {
            log.line(&format!(
                "The server cannot write stdout: {error}. The server stops."
            ));
            return Exit::Usage;
        }
        Err(_) => return Exit::Usage,
    }
    if worker.join().is_err() {
        log.line("The worker thread stops after a fault. The server stops.");
        return Exit::Usage;
    }
    let _ = reader.join();
    log.line("stdin is closed. The server stops.");
    Exit::Ok
}
