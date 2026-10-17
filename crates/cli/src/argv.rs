//! The command-line parser (design Section 10.14).
//!
//! | Command | Flags |
//! |---|---|
//! | `mcp` | `--project-root DIR`, `--root DIR`..., `--profile P`, `--tools a,b`, `--read-only`, `--open BIN_ID`..., `--record FILE`, `--content MODE`, `--break-lock` |
//! | `call <tool> [<json> \| @file \| -]` | `--project-root DIR`, `--root DIR`..., `--select PTR`, `--format F`, `--source S`, `--session NAME` |
//! | `jsonl` | `--project-root DIR`, `--root DIR`..., `--source S`, `--session NAME` |
//! | `tools` | `--json`, `--profile P` |
//! | `doctor` | `--project-root DIR` |
//!
//! A flag value follows the flag as the next argument or after `=`.
//! An unknown command or flag gives a [`UsageError`] with did-you-mean candidates.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use ghidorah_json::pointer::Pointer;
use ghidorah_tools::{ContentMode, Profile};

use crate::backend::Source;

/// The usage text of `ghidorah --help`.
pub const USAGE: &str = "\
ghidorah: reverse engineering tools for AI agents. No tool runs the binary.

Usage:
  ghidorah mcp [--project-root DIR] [--root DIR]... [--profile full|readonly|mini]
               [--tools a,b] [--read-only] [--open BIN_ID]... [--record FILE]
               [--content both|structured|text] [--break-lock]
  ghidorah call <tool> [<json> | @file | -] [--project-root DIR] [--root DIR]...
               [--select PTR] [--format json|jsonl|text] [--source agent|user]
               [--session NAME]
  ghidorah jsonl [--project-root DIR] [--root DIR]... [--source agent|user]
               [--session NAME]
  ghidorah tools [--json] [--profile full|readonly|mini]
  ghidorah doctor [--project-root DIR]
  ghidorah --version
  ghidorah --help

Exit codes: 0 success, 1 tool error, 2 usage or protocol error.
";

/// The command names.
pub const COMMANDS: [&str; 5] = ["mcp", "call", "jsonl", "tools", "doctor"];

/// The session flags of `mcp`, `call` and `jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionFlags {
    /// `--project-root DIR`.
    pub project_root: Option<PathBuf>,
    /// `--root DIR`, in flag order.
    pub roots: Vec<PathBuf>,
    /// `--profile P`, or `None` for `full`.
    pub profile: Option<Profile>,
    /// `--tools a,b`.
    pub tools: Option<BTreeSet<String>>,
    /// `--read-only`.
    pub read_only: bool,
    /// `--open BIN_ID`, in flag order.
    pub open: Vec<String>,
    /// `--break-lock`.
    pub break_lock: bool,
    /// `--source agent|user`.
    pub source: Source,
    /// `--session NAME`.
    pub session: Option<String>,
}

/// The arguments of `ghidorah mcp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpArgs {
    /// The session flags.
    pub session: SessionFlags,
    /// `--record FILE`.
    pub record: Option<PathBuf>,
    /// `--content MODE`. The default is [`ContentMode::Both`].
    pub content: ContentMode,
}

/// The source of the tool arguments of `ghidorah call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgsInput {
    /// No argument text: the arguments are `{}`.
    Empty,
    /// JSON text on the command line.
    Inline(String),
    /// `@file`: JSON text in a file.
    File(PathBuf),
    /// `-`: JSON text on stdin.
    Stdin,
}

/// The print format of `ghidorah call`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrintFormat {
    /// Pretty JSON with an indent of 2 spaces. This is the default.
    #[default]
    Json,
    /// Compact JSON on one line.
    Jsonl,
    /// One line per scalar value: the JSON pointer, a space and the value.
    Text,
}

/// The arguments of `ghidorah call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallArgs {
    /// The session flags.
    pub session: SessionFlags,
    /// The tool name.
    pub tool: String,
    /// The source of the tool arguments.
    pub input: ArgsInput,
    /// `--select PTR`.
    pub select: Option<Pointer>,
    /// `--format F`.
    pub format: PrintFormat,
}

/// The arguments of `ghidorah tools`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolsArgs {
    /// `--json`.
    pub json: bool,
    /// `--profile P`. The default is [`Profile::Full`].
    pub profile: Profile,
}

/// The arguments of `ghidorah doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DoctorArgs {
    /// `--project-root DIR`.
    pub project_root: Option<PathBuf>,
}

/// One parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `ghidorah mcp`.
    Mcp(McpArgs),
    /// `ghidorah call`.
    Call(CallArgs),
    /// `ghidorah jsonl`.
    Jsonl(SessionFlags),
    /// `ghidorah tools`.
    Tools(ToolsArgs),
    /// `ghidorah doctor`.
    Doctor(DoctorArgs),
    /// `ghidorah --version`.
    Version,
    /// `ghidorah --help`.
    Help,
}

/// A command line that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError {
    /// What failed and what to do, in STE.
    pub message: String,
    /// The did-you-mean candidates, best first.
    pub candidates: Vec<String>,
}

impl UsageError {
    /// Makes an error with `message` and no candidates.
    #[must_use]
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            candidates: Vec::new(),
        }
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(best) = self.candidates.first() {
            write!(f, " Did you mean {best}?")?;
        }
        f.write_str(" Run ghidorah --help to see the usage.")
    }
}

impl std::error::Error for UsageError {}

/// Parses a command line without the program name.
///
/// # Errors
///
/// Returns [`UsageError`] for an unknown command or flag, a missing or bad flag value, a
/// missing tool name or an extra argument.
pub fn parse(args: &[String]) -> Result<Command, UsageError> {
    let _ = args;
    Err(UsageError::new("The command line does not parse."))
}
