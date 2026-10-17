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

mod flags;

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use ghidorah_json::pointer::{self, Pointer};
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

/// The top-level flags.
const TOP_FLAGS: [&str; 4] = ["--version", "-V", "--help", "-h"];

fn mcp(args: &[String]) -> Result<Command, UsageError> {
    let scan = flags::scan("mcp", args, flags::MCP)?;
    scan.no_positional()?;
    let content = scan
        .one(flags::CONTENT)
        .map(|text| {
            ContentMode::parse(text)
                .ok_or_else(|| flags::bad_value(flags::CONTENT, text, "both, structured or text"))
        })
        .transpose()?
        .unwrap_or(ContentMode::Both);
    Ok(Command::Mcp(McpArgs {
        session: flags::session(&scan)?,
        record: scan.one(flags::RECORD).map(PathBuf::from),
        content,
    }))
}

fn call(args: &[String]) -> Result<Command, UsageError> {
    let scan = flags::scan("call", args, flags::CALL)?;
    let mut positional = scan.positional.iter();
    let tool = positional
        .next()
        .cloned()
        .ok_or_else(|| UsageError::new("The command call needs a tool name."))?;
    let input = match positional.next().map(String::as_str) {
        None => ArgsInput::Empty,
        Some("-") => ArgsInput::Stdin,
        Some(text) => text.strip_prefix('@').map_or_else(
            || ArgsInput::Inline(text.to_owned()),
            |path| ArgsInput::File(PathBuf::from(path)),
        ),
    };
    if let Some(arg) = positional.next() {
        return Err(flags::extra(arg));
    }
    let select = scan
        .one(flags::SELECT)
        .map(|text| {
            pointer::parse(text).map_err(|_| {
                flags::bad_value(
                    flags::SELECT,
                    text,
                    "a JSON pointer such as /data/items/*/id",
                )
            })
        })
        .transpose()?;
    let format = match scan.one(flags::FORMAT) {
        None | Some("json") => PrintFormat::Json,
        Some("jsonl") => PrintFormat::Jsonl,
        Some("text") => PrintFormat::Text,
        Some(text) => return Err(flags::bad_value(flags::FORMAT, text, "json, jsonl or text")),
    };
    Ok(Command::Call(CallArgs {
        session: flags::session(&scan)?,
        tool,
        input,
        select,
        format,
    }))
}

/// Parses a command line without the program name.
///
/// # Errors
///
/// Returns [`UsageError`] for an unknown command or flag, a missing or bad flag value, a
/// missing tool name or an extra argument.
pub fn parse(args: &[String]) -> Result<Command, UsageError> {
    let Some((first, rest)) = args.split_first() else {
        return Err(UsageError::new("The command line has no command."));
    };
    let alone = |command: Command| {
        rest.first()
            .map_or(Ok(command), |arg| Err(flags::extra(arg)))
    };
    match first.as_str() {
        "--version" | "-V" => alone(Command::Version),
        "--help" | "-h" => alone(Command::Help),
        "mcp" => mcp(rest),
        "call" => call(rest),
        "jsonl" => {
            let scan = flags::scan("jsonl", rest, flags::JSONL)?;
            scan.no_positional()?;
            Ok(Command::Jsonl(flags::session(&scan)?))
        }
        "tools" => {
            let scan = flags::scan("tools", rest, flags::TOOLS_COMMAND)?;
            scan.no_positional()?;
            Ok(Command::Tools(ToolsArgs {
                json: scan.has(flags::JSON),
                profile: flags::profile(&scan)?.unwrap_or(Profile::Full),
            }))
        }
        "doctor" => {
            let scan = flags::scan("doctor", rest, flags::DOCTOR)?;
            scan.no_positional()?;
            Ok(Command::Doctor(DoctorArgs {
                project_root: scan.one(flags::PROJECT_ROOT).map(PathBuf::from),
            }))
        }
        other if other.starts_with('-') => Err(UsageError {
            message: format!("The flag {other} is not known."),
            candidates: flags::closest(other, TOP_FLAGS.into_iter()),
        }),
        other => Err(UsageError {
            message: format!("The command {other} is not known."),
            candidates: flags::closest(other, COMMANDS.into_iter()),
        }),
    }
}
