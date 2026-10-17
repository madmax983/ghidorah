//! `ghidorah tools` and the `tools/list` result (design Sections 10.3 and 10.14).
//!
//! The catalog holds the tools of the active profile in registry order (AC-174).
//! `ghidorah tools --json` prints the `tools/list` result `{ tools }` (AC-149b).
//! `ghidorah tools` prints one line per tool: the name and the summary.

use ghidorah_json::Value;

use crate::Streams;
use crate::argv::ToolsArgs;
use crate::backend::Backend;
use crate::config::Env;
use crate::exit::Exit;

/// Gives the names of the tools of the active profile of `backend`, in registry order.
#[must_use]
pub fn names<B: Backend>(backend: &B) -> Vec<&'static str> {
    let _ = backend;
    Vec::new()
}

/// Gives the `tools/list` result `{ tools }` of `backend`.
#[must_use]
pub fn tools_list<B: Backend>(backend: &B) -> Value {
    let _ = backend;
    Value::Null
}

/// Gives the text catalog: one line `name  summary` per tool.
#[must_use]
pub fn text<B: Backend>(backend: &B) -> String {
    let _ = backend;
    String::new()
}

/// Runs `ghidorah tools` with the backend `B`.
pub fn tools<B: Backend>(args: ToolsArgs, env: &Env, streams: &mut Streams) -> Exit {
    let _ = (args, env, streams);
    Exit::Usage
}
