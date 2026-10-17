//! The call API of the tool surface (design Sections 10.1 and 10.6).
//!
//! Every surface sends one [`Request`] per tool call and gets one [`Envelope`]:
//! the MCP server, `ghidorah call`, `ghidorah jsonl` and `batch_run` steps.
//! [`dispatch`] runs the shipped registry of the host. [`dispatch_with`] runs any registry,
//! so tests can inject test tools, for example a tool that panics (AC-148).

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;

use ghidorah_json::Value;

use crate::args::Globals;
use crate::content::ContentMode;
use crate::dispatch::{self, Crash, CursorCall, Members, SortKey};
pub use crate::envelope::Envelope;
use crate::envelope::Frame;
use crate::errors::ToolError;
use crate::registry::Registry;
use crate::spec::{ArgKind, ToolSpec};

/// One progress report of a long call (design Section 10.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    /// The progress value. It increases strictly within one request.
    pub progress: u64,
    /// The total, or `None` when the host has no total.
    pub total: Option<u64>,
    /// One STE sentence about the work.
    pub message: String,
}

/// One tool call.
#[derive(Debug, Clone)]
pub struct Request {
    /// The tool name.
    pub tool: String,
    /// The arguments: a JSON object.
    pub args: Value,
    /// The session label from the transport, for example `_meta["dev.ghidorah/session"]`.
    pub session: Option<String>,
    /// The content mode of the result. It sets the copies of the budget.
    pub content: ContentMode,
    /// The cancel flag of the request.
    pub cancel: Option<Arc<AtomicBool>>,
    /// The channel of the progress reports.
    pub progress: Option<Sender<Progress>>,
}

impl Request {
    /// Makes a request in [`ContentMode::Plain`] with no session label, cancel flag or
    /// progress channel.
    #[must_use]
    pub fn new(tool: &str, args: Value) -> Self {
        Self {
            tool: tool.to_owned(),
            args,
            session: None,
            content: ContentMode::Plain,
            cancel: None,
            progress: None,
        }
    }
}

/// The session side of the dispatcher.
///
/// The session type of WP-13b implements it. Tests implement it for small test hosts.
pub trait Host: Sized + 'static {
    /// Gives the shipped registry that [`dispatch`] runs.
    fn registry() -> Registry<Self>;

    /// Tells if the active profile holds the tool `name`.
    fn in_profile(&self, name: &str) -> bool;

    /// Opens the frame of one call: the bound binary, its rev, the session label and the
    /// analysis state.
    ///
    /// `request_session` is the session label of the transport.
    ///
    /// # Errors
    ///
    /// Returns `NO_BINARY_OPEN`, `BINARY_REQUIRED` or `UNKNOWN_BINARY` when the call
    /// cannot bind a binary.
    fn frame(
        &mut self,
        tool: &ToolSpec<Self>,
        globals: &Globals,
        request_session: Option<&str>,
    ) -> Result<Frame, ToolError>;

    /// Gives the lenient coercion of `value` to `kind`, or `None` (design Section 10.2).
    fn coerce(&self, kind: &ArgKind, value: &Value) -> Option<Value>;

    /// Gives the members of the named set `set` of the bound binary.
    ///
    /// # Errors
    ///
    /// Returns `NOT_FOUND` when the set does not exist.
    fn members(&self, frame: &Frame, set: &str) -> Result<Members, ToolError>;

    /// Gives the cursor text that points after the item with `key`.
    fn encode_cursor(&self, call: &CursorCall<'_>, key: &SortKey) -> String;

    /// Gives the sort key of the last item of the previous page.
    ///
    /// # Errors
    ///
    /// Returns `CURSOR_INVALID` or `CURSOR_STALE`.
    fn decode_cursor(&self, call: &CursorCall<'_>, cursor: &str) -> Result<SortKey, ToolError>;

    /// Tells the host about a handler panic, so that it can write a crash file and reload.
    fn on_panic(&mut self, crash: &Crash);
}

/// Runs one request through the shipped registry of the host.
pub fn dispatch<S: Host>(host: &mut S, request: &Request) -> Envelope {
    dispatch_with(&S::registry(), host, request)
}

/// Runs one request through `registry`.
///
/// The pipeline never panics. A handler panic gives an `INTERNAL_ERROR` envelope.
pub fn dispatch_with<S: Host>(registry: &Registry<S>, host: &mut S, request: &Request) -> Envelope {
    dispatch::run(registry, host, request)
}
