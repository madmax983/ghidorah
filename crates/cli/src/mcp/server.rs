//! The request handler of the worker thread (design Section 10.13).
//!
//! [`Server`] owns the backend and the era state of one process. [`Server::handle`] answers
//! one request. [`Server::handle_line`] classifies and answers one line with no threads, for
//! golden transcripts and the fuzz target.
//!
//! | Method | Result |
//! |---|---|
//! | `initialize` | [`era::initialize_result`] |
//! | `server/discover` | [`era::discover_result`] |
//! | `ping` | `{}` |
//! | `tools/list` | `{ tools }`: the active profile in registry order |
//! | `tools/call` | The tool result of the content mode, with `_meta["dev.ghidorah/size"]` |
//!
//! A `tools/call` of a name outside the registry gives -32602 with
//! `data: { code: "UNKNOWN_TOOL", candidates, next }`. A tool failure gives `isError: true`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;

use ghidorah_base::Clock;
use ghidorah_json::{Object, Value};
use ghidorah_tools::content::{result_chars, tool_result};
use ghidorah_tools::{ContentMode, dispatch};

use crate::backend::Backend;
use crate::catalog;
use crate::mcp::era::{self, EraState, Method};
use crate::mcp::frame::{Frame, MAX_LINE};
use crate::mcp::progress;
use crate::mcp::rpc::{self, Message, Request};
use crate::record::Recorder;

/// The characters per token of the size report (design Section 10.9).
pub const CHARS_PER_TOKEN: u64 = 3;

/// The message of a line above the cap.
const TOO_LONG: &str =
    "The line is longer than 16 MiB. Send each message on one line of at most 16 MiB.";

/// The message of a `tools/call` with no tool name.
const NO_NAME: &str =
    "The params of tools/call have no string name. Send the tool name in params.name.";

/// The message of `tools/call` arguments that are not an object.
const ARGS_NOT_OBJECT: &str =
    "The params.arguments member is not an object. Send the tool arguments as an object.";

/// The error code of a tool name outside the registry.
const UNKNOWN_TOOL: &str = "UNKNOWN_TOOL";

/// Gives the error reply of a line above the cap: -32600 with `id: null`.
#[must_use]
pub fn too_long(bytes: usize) -> Value {
    let data = Value::object([
        ("max_bytes", Value::from(MAX_LINE)),
        ("bytes", Value::from(bytes)),
    ]);
    rpc::error(None, rpc::INVALID_REQUEST, TOO_LONG, Some(data))
}

/// Tells if `line` holds only white space.
pub(crate) fn is_blank(line: &[u8]) -> bool {
    line.iter().all(u8::is_ascii_whitespace)
}

/// Gives the size report `{ chars, copies, est_tokens }` of a tool result.
fn size_report(chars: u64, copies: u64) -> Value {
    Value::object([
        ("chars", Value::from(chars)),
        ("copies", Value::from(copies)),
        ("est_tokens", Value::from(chars.div_ceil(CHARS_PER_TOKEN))),
    ])
}

/// The request handler of one process.
pub struct Server<B: Backend> {
    backend: B,
    era: EraState,
    content: ContentMode,
    info: Value,
    recorder: Option<Recorder>,
    clock: Box<dyn Clock + Send>,
}

impl<B: Backend> Server<B> {
    /// Makes a handler over `backend` with the content mode `content` and the clock `clock`.
    ///
    /// The clock measures the `ms` of the call recorder only.
    pub fn new(backend: B, content: ContentMode, clock: Box<dyn Clock + Send>) -> Self {
        Self {
            backend,
            era: EraState::default(),
            content,
            info: era::server_info(crate::VERSION),
            recorder: None,
            clock,
        }
    }

    /// Adds a call recorder.
    #[must_use]
    pub fn with_recorder(mut self, recorder: Recorder) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// Takes the first write error of the call recorder, if any.
    pub fn take_record_error(&mut self) -> Option<std::io::Error> {
        self.recorder.as_mut().and_then(Recorder::take_error)
    }

    /// Answers one request.
    ///
    /// `emit` gets each progress notification while the tool runs. Gives the reply, or
    /// `None` when the client cancelled the request.
    pub fn handle(
        &mut self,
        request: &Request,
        cancel: &Arc<AtomicBool>,
        emit: &(dyn Fn(Value) + Sync),
    ) -> Option<Value> {
        let cancelled = || cancel.load(Ordering::Relaxed);
        if cancelled() {
            return None;
        }
        let start = self.clock.monotonic_ms();
        let (reply, copies) = self.answer(request, cancel, emit);
        if cancelled() {
            return None;
        }
        let ms = self.clock.monotonic_ms().saturating_sub(start);
        if let Some(recorder) = &mut self.recorder {
            recorder.record(&request.message, &reply, copies, ms);
        }
        Some(reply)
    }

    /// Gives the reply of one request and the envelope copies in it.
    fn answer(
        &mut self,
        request: &Request,
        cancel: &Arc<AtomicBool>,
        emit: &(dyn Fn(Value) + Sync),
    ) -> (Value, u64) {
        let (era, method) =
            match era::decide(&mut self.era, &request.method, request.params.as_ref()) {
                Ok(decision) => decision,
                Err(r) => return (rpc::error(Some(&request.id), r.code, &r.message, r.data), 0),
            };
        let mut copies = 0;
        let result = match method {
            Method::Initialize(version) => {
                era::initialize_result(version, &self.info, &self.backend.instructions())
            }
            Method::Discover => era::discover_result(&self.info, &self.backend.instructions()),
            Method::Ping => Value::Object(Object::new()),
            Method::ToolsList => catalog::tools_list(&self.backend),
            Method::ToolsCall => match self.tools_call(request, cancel, emit) {
                Ok(result) => {
                    copies = self.content.copies();
                    result
                }
                Err(reply) => return (reply, 0),
            },
        };
        (rpc::result(&request.id, era::finish(era, result)), copies)
    }

    /// Runs one `tools/call`. Gives the tool result, or the error reply of a bad call.
    fn tools_call(
        &mut self,
        request: &Request,
        cancel: &Arc<AtomicBool>,
        emit: &(dyn Fn(Value) + Sync),
    ) -> Result<Value, Value> {
        let invalid =
            |message: &str| rpc::error(Some(&request.id), rpc::INVALID_PARAMS, message, None);
        let params = request.params.as_ref();
        let name = params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(NO_NAME))?;
        let args = match params.and_then(|p| p.get("arguments")) {
            None => Value::Object(Object::new()),
            Some(Value::Object(args)) => Value::Object(args.clone()),
            Some(_) => return Err(invalid(ARGS_NOT_OBJECT)),
        };
        let meta = params.and_then(|p| p.get("_meta"));
        let token = meta
            .and_then(|m| m.get("progressToken"))
            .filter(|t| rpc::RequestId::of(t).is_some())
            .cloned();
        let mut call = ghidorah_tools::Request::new(name, args);
        call.session = meta
            .and_then(|m| m.get(era::SESSION_KEY))
            .and_then(Value::as_str)
            .map(str::to_owned);
        call.content = self.content;
        call.cancel = Some(Arc::clone(cancel));
        let envelope = match token {
            None => dispatch(&mut self.backend, &call),
            Some(token) => {
                let (sender, reports) = mpsc::channel();
                call.progress = Some(sender);
                let backend = &mut self.backend;
                thread::scope(|scope| {
                    let forwarder = scope.spawn(move || progress::forward(&reports, &token, emit));
                    let envelope = dispatch(backend, &call);
                    drop(call);
                    let _ = forwarder.join();
                    envelope
                })
            }
        };
        let json = envelope.to_json();
        let ok = envelope.ok();
        if !ok && json.pointer("/error/code").and_then(Value::as_str) == Some(UNKNOWN_TOOL) {
            let pick = |pointer: &str| {
                json.pointer(pointer)
                    .cloned()
                    .unwrap_or(Value::Array(Vec::new()))
            };
            let data = Value::object([
                ("code", Value::from(UNKNOWN_TOOL)),
                ("candidates", pick("/error/candidates")),
                ("next", pick("/next")),
            ]);
            let message = json
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or(UNKNOWN_TOOL);
            return Err(rpc::error(
                Some(&request.id),
                rpc::INVALID_PARAMS,
                message,
                Some(data),
            ));
        }
        let mut result = tool_result(&json, !ok, self.content);
        let size = size_report(
            result_chars(&json, !ok, self.content),
            self.content.copies(),
        );
        if let Some(object) = result.as_object_mut() {
            object.push("_meta", Value::object([(era::SIZE_KEY, size)]));
        }
        Ok(result)
    }

    /// Classifies and answers one line in order. Gives the output lines.
    pub fn handle_line(&mut self, line: &[u8]) -> Vec<String> {
        if is_blank(line) {
            return Vec::new();
        }
        match rpc::classify(line) {
            Err(reply) => vec![ghidorah_json::write(&reply)],
            Ok(Message::Request(request)) => {
                let lines = Mutex::new(Vec::new());
                let emit = |message: Value| {
                    lines
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(ghidorah_json::write(&message));
                };
                let flag = Arc::new(AtomicBool::new(false));
                let reply = self.handle(&request, &flag, &emit);
                let mut out = lines.into_inner().unwrap_or_else(PoisonError::into_inner);
                out.extend(reply.map(|r| ghidorah_json::write(&r)));
                out
            }
            Ok(Message::Notification { .. } | Message::Reply) => Vec::new(),
        }
    }

    /// Answers one framed line in order. Gives the output lines.
    pub fn handle_frame(&mut self, frame: &Frame) -> Vec<String> {
        match frame {
            Frame::Line(bytes) => self.handle_line(bytes),
            Frame::TooLong { bytes } => vec![ghidorah_json::write(&too_long(*bytes))],
        }
    }
}
