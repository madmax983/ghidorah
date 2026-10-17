//! The backend of the `ghidorah` binary: the [`Session`] of the tools crate.
//!
//! [`Shipped`] names the one backend type of the binary. Tests that run the shipped registry
//! use this name, so they follow the binary.
//!
//! [`Backend::open`] makes the session of one command from its [`Options`]:
//!
//! | Session setting | Source |
//! |---|---|
//! | Roots | `--root` in flag order, else `.`. A relative root starts at the current directory. |
//! | Profile | `--profile` and the `--tools` allowlist. A name that is not a tool is a usage error. |
//! | Session labels | `mcp-<k>` for `ghidorah mcp`, else `--session` or `cli` |
//! | Read-only mode | `--read-only` |
//! | Run settings and clock | `GHIDORAH_FIXED_TIME` and `GHIDORAH_EVAL` through [`crate::RunConfig`] |
//!
//! This build keeps no projects on disk. So `--open` is an open error.

use ghidorah_json::Value;
use ghidorah_tools::{Host, ProfileSet, Request, Roots, Session, SessionConfig, dispatch};

use crate::backend::{Backend, OpenError, Options};

/// The backend of the `ghidorah` binary.
pub type Shipped = Session;

/// The built-in binary that the registry examples use.
pub const EXAMPLE_BINARY: &str = "demo";

/// Gives the session settings of `options`.
///
/// # Errors
///
/// Returns [`OpenError`] for a bad root list. An allowlist name that is not a tool also gives
/// [`OpenError`].
pub fn session_config(options: &Options) -> Result<SessionConfig, OpenError> {
    let roots =
        Roots::new(&options.cwd, &options.roots).map_err(|e| OpenError::new(&e.to_string()))?;
    let allow = options
        .tools
        .as_ref()
        .map(|names| names.iter().cloned().collect());
    let profile = ProfileSet::new(options.profile, allow);
    let unknown = profile.unknown(&<Session as Host>::registry());
    if !unknown.is_empty() {
        return Err(OpenError::new(&format!(
            "The --tools list has names that are not tools: {}. Run ghidorah tools to see the tool names.",
            unknown.join(", ")
        )));
    }
    let mut config = SessionConfig::new(roots);
    config.profile = profile;
    config.run = options.run.into();
    config.labels = options.labels.clone();
    config.read_only = options.read_only;
    Ok(config)
}

impl Backend for Session {
    fn open(options: &Options) -> Result<Self, OpenError> {
        if let Some(id) = options.open.first() {
            return Err(OpenError::new(&format!(
                "The project {id} does not open. This build keeps no projects. Remove the --open flag."
            )));
        }
        let config = session_config(options)?;
        Ok(Self::new(config, options.run.clock()))
    }

    fn for_examples(options: &Options) -> Result<Self, OpenError> {
        let mut session = <Self as Backend>::open(options)?;
        let args = Value::object([("builtin", Value::from(EXAMPLE_BINARY))]);
        let envelope = dispatch(&mut session, &Request::new("binary_load", args)).to_json();
        match envelope.pointer("/error/code").and_then(Value::as_str) {
            None => Ok(session),
            Some(code) => Err(OpenError::new(&format!(
                "The demo binary does not load: {code}. Use a profile that has the tool binary_load."
            ))),
        }
    }

    fn instructions(&self) -> String {
        Self::instructions(self)
    }

    fn tools_list(&self) -> Value {
        let tools = self.config().profile.tools_list(&self.active_registry());
        Value::object([("tools", tools)])
    }
}

#[cfg(test)]
mod tests;
