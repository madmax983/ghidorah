//! `ghidorah tools` and the `tools/list` result (design Sections 10.3 and 10.14).
//!
//! The catalog holds the tools of the active profile in registry order (AC-174).
//! `ghidorah tools --json` prints the `tools/list` result `{ tools }` (AC-149b).
//! `ghidorah tools` prints one line per tool: the name and the summary.

use ghidorah_json::Value;
use ghidorah_tools::schema::tool_entry;

use crate::Streams;
use crate::argv::ToolsArgs;
use crate::backend::{Backend, Options};
use crate::call::SESSION;
use crate::config::Env;
use crate::exit::Exit;
use crate::out;

/// Gives the names of the tools of the active profile of `backend`, in registry order.
#[must_use]
pub fn names<B: Backend>(backend: &B) -> Vec<&'static str> {
    B::registry()
        .tools()
        .iter()
        .map(|tool| tool.name)
        .filter(|name| backend.in_profile(name))
        .collect()
}

/// Gives the `tools/list` result `{ tools }` of `backend`.
#[must_use]
pub fn tools_list<B: Backend>(backend: &B) -> Value {
    let tools = B::registry()
        .tools()
        .iter()
        .filter(|tool| backend.in_profile(tool.name))
        .map(|tool| tool_entry(tool))
        .collect();
    Value::object([("tools", Value::Array(tools))])
}

/// Gives the text catalog: one line `name  summary` per tool.
#[must_use]
pub fn text<B: Backend>(backend: &B) -> String {
    let registry = B::registry();
    let tools: Vec<_> = registry
        .tools()
        .iter()
        .filter(|tool| backend.in_profile(tool.name))
        .collect();
    let width = tools.iter().map(|t| t.name.len()).max().unwrap_or(0);
    tools
        .iter()
        .map(|tool| format!("{:<width$}  {}", tool.name, tool.summary))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Runs `ghidorah tools` with the backend `B`.
pub fn tools<B: Backend>(args: ToolsArgs, env: &Env, streams: &mut Streams) -> Exit {
    let mut options = Options::new(env, SESSION);
    options.profile = args.profile;
    let backend = match B::open(&options) {
        Ok(backend) => backend,
        Err(error) => {
            out::log(&mut streams.stderr, &error.message);
            return Exit::Usage;
        }
    };
    let text = if args.json {
        ghidorah_json::write(&tools_list(&backend))
    } else {
        text(&backend)
    };
    if text.is_empty() {
        return Exit::Ok;
    }
    match out::line(&mut streams.stdout, &text) {
        Ok(()) => Exit::Ok,
        Err(stop) => stop.exit(),
    }
}
