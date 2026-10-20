//! The MCP stdio server (design Sections 2.4 and 10.13, ADR-0003, ADR-0006).
//!
//! One `ghidorah mcp` process has three threads:
//!
//! | Thread | Work |
//! |---|---|
//! | reader | Frames stdin lines with the 16 MiB cap ([`frame`]), parses and classifies them ([`rpc`]). It sets the cancel flags of `notifications/cancelled` ([`cancel`]). |
//! | worker | Owns the backend. It runs the requests in arrival order through [`server::Server`], with a 64 MiB stack. |
//! | writer | The only writer of stdout. It writes one line and flushes. |
//!
//! While the work queue has room, the reader sends each error reply through it, so the output
//! order is the input order. When the queue is full, the reader sends the reply to the writer
//! at once. A broken pipe on stdout ends the server with exit code 0.
//! [`era`] holds every rule of the two protocol eras.

pub mod cancel;
pub mod era;
pub mod frame;
pub mod progress;
pub mod rpc;
pub mod server;

mod threads;

use std::path::PathBuf;

use ghidorah_tools::ContentMode;

use crate::Streams;
use crate::backend::{Backend, Options};
use crate::exit::Exit;

/// The server settings of `ghidorah mcp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeOptions {
    /// The content mode of each `tools/call` result.
    pub content: ContentMode,
    /// The call record file of `--record FILE`, or `None`.
    pub record: Option<PathBuf>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            content: ContentMode::Both,
            record: None,
        }
    }
}

/// Serves MCP on `streams` until stdin ends or stdout breaks.
///
/// Gives [`Exit::Ok`] at the end of stdin and on a broken pipe. Gives [`Exit::Usage`] when
/// the backend or the record file does not open, or when stdout fails.
#[must_use]
pub fn serve<B: Backend>(options: Options, serve: &ServeOptions, streams: Streams) -> Exit {
    threads::serve::<B>(options, serve, streams)
}
