//! `ghidorah call` and `ghidorah jsonl` (design Section 10.14).
//!
//! `call` runs one tool call and prints its envelope on stdout. The exit code is 0 for
//! `ok: true` and 1 for `ok: false`. Bad arguments of the command line give exit code 2.
//!
//! `jsonl` reads independent requests `{ "id", "tool", "args" }` from stdin, one per line.
//! It writes one line per request: the envelope with the `id` of the request as its first
//! member. A line that is not a request gives a failure line with `INVALID_ARGUMENT`.
//! The exit code is the most severe code of all lines: 2 for a bad line, else 1 for a tool
//! error, else 0.

use ghidorah_json::Value;

use crate::Streams;
use crate::argv::{CallArgs, PrintFormat, SessionFlags};
use crate::backend::{Backend, Options};
use crate::config::Env;
use crate::exit::Exit;

/// The default session label of `call` and `jsonl`.
pub const SESSION: &str = "cli";

/// Gives the backend options of the session flags `flags` in `env`.
///
/// Relative paths start at the current directory of `env`.
#[must_use]
pub fn options(flags: &SessionFlags, env: &Env, session: &str) -> Options {
    let _ = flags;
    Options::new(env, session)
}

/// Gives the text lines of format [`PrintFormat::Text`]: one line per scalar value, with
/// the JSON pointer, a space and the value. A string prints without quotes.
#[must_use]
pub fn text_lines(value: &Value) -> Vec<String> {
    let _ = value;
    Vec::new()
}

/// Gives the stdout text of `envelope` in `format`, without the last line end.
#[must_use]
pub fn render(envelope: &Value, format: PrintFormat) -> String {
    let _ = (envelope, format);
    String::new()
}

/// Runs `ghidorah call` with the backend `B`.
pub fn call<B: Backend>(args: &CallArgs, env: &Env, streams: &mut Streams) -> Exit {
    let _ = (args, env, streams);
    Exit::Usage
}

/// Runs `ghidorah call` on the open backend `backend`.
pub fn call_on<B: Backend>(backend: &mut B, args: &CallArgs, streams: &mut Streams) -> Exit {
    let _ = (backend, args, streams);
    Exit::Usage
}

/// Runs `ghidorah jsonl` with the backend `B`.
pub fn jsonl<B: Backend>(flags: &SessionFlags, env: &Env, streams: &mut Streams) -> Exit {
    let _ = (flags, env, streams);
    Exit::Usage
}

/// Runs `ghidorah jsonl` on the open backend `backend` with the session label `session`.
pub fn jsonl_on<B: Backend>(backend: &mut B, session: Option<&str>, streams: &mut Streams) -> Exit {
    let _ = (backend, session, streams);
    Exit::Usage
}
