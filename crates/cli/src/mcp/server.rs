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

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use ghidorah_base::Clock;
use ghidorah_json::Value;
use ghidorah_tools::ContentMode;

use crate::backend::Backend;
use crate::mcp::era::{self, EraState};
use crate::mcp::frame::{Frame, MAX_LINE};
use crate::mcp::rpc::{self, Request};
use crate::record::Recorder;

/// The name of the server in `serverInfo`.
pub const SERVER_NAME: &str = "ghidorah";

/// The characters per token of the size report (design Section 10.9).
pub const CHARS_PER_TOKEN: u64 = 3;

/// Gives the error reply of a line above the cap: -32600 with `id: null`.
#[must_use]
pub fn too_long(bytes: usize) -> Value {
    let _ = (bytes, MAX_LINE);
    Value::Null
}

/// The request handler of one process.
pub struct Server<B: Backend> {
    backend: B,
    era: EraState,
    content: ContentMode,
    server_info: Value,
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
            server_info: era::server_info(crate::VERSION),
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

    /// Gives the backend.
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Gives the era state.
    pub const fn era(&self) -> &EraState {
        &self.era
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
        let _ = (
            request,
            cancel,
            emit,
            &mut self.backend,
            &mut self.era,
            self.content,
            &self.server_info,
            &mut self.recorder,
            &self.clock,
            rpc::JSONRPC,
        );
        None
    }

    /// Classifies and answers one line in order. Gives the output lines.
    pub fn handle_line(&mut self, line: &[u8]) -> Vec<String> {
        let _ = line;
        Vec::new()
    }

    /// Answers one framed line in order. Gives the output lines.
    pub fn handle_frame(&mut self, frame: &Frame) -> Vec<String> {
        let _ = frame;
        Vec::new()
    }
}
