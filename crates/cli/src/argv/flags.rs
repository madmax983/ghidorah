//! The flag tables of the commands and the flag scanner.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use ghidorah_base::{Fuel, did_you_mean};
use ghidorah_tools::Profile;

use super::{SessionFlags, UsageError};
use crate::backend::{Source, parse_profile};

/// One flag of a command.
#[derive(Debug, Clone, Copy)]
pub struct Flag {
    /// The flag with its `--` prefix.
    pub name: &'static str,
    /// `true` when the flag takes a value.
    pub value: bool,
    /// `true` when the flag can occur more than once.
    pub repeat: bool,
}

impl Flag {
    const fn switch(name: &'static str) -> Self {
        Self {
            name,
            value: false,
            repeat: false,
        }
    }

    const fn value(name: &'static str) -> Self {
        Self {
            name,
            value: true,
            repeat: false,
        }
    }

    const fn list(name: &'static str) -> Self {
        Self {
            name,
            value: true,
            repeat: true,
        }
    }
}

/// `--project-root DIR`.
pub const PROJECT_ROOT: Flag = Flag::value("--project-root");
/// `--root DIR`.
pub const ROOT: Flag = Flag::list("--root");
/// `--profile P`.
pub const PROFILE: Flag = Flag::value("--profile");
/// `--tools a,b`.
pub const TOOLS: Flag = Flag::value("--tools");
/// `--read-only`.
pub const READ_ONLY: Flag = Flag::switch("--read-only");
/// `--open BIN_ID`.
pub const OPEN: Flag = Flag::list("--open");
/// `--record FILE`.
pub const RECORD: Flag = Flag::value("--record");
/// `--content MODE`.
pub const CONTENT: Flag = Flag::value("--content");
/// `--break-lock`.
pub const BREAK_LOCK: Flag = Flag::switch("--break-lock");
/// `--select PTR`.
pub const SELECT: Flag = Flag::value("--select");
/// `--format F`.
pub const FORMAT: Flag = Flag::value("--format");
/// `--source S`.
pub const SOURCE: Flag = Flag::value("--source");
/// `--session NAME`.
pub const SESSION: Flag = Flag::value("--session");
/// `--json`.
pub const JSON: Flag = Flag::switch("--json");

/// The flags of `mcp`.
pub const MCP: &[Flag] = &[
    PROJECT_ROOT,
    ROOT,
    PROFILE,
    TOOLS,
    READ_ONLY,
    OPEN,
    RECORD,
    CONTENT,
    BREAK_LOCK,
];
/// The flags of `call`.
pub const CALL: &[Flag] = &[PROJECT_ROOT, ROOT, SELECT, FORMAT, SOURCE, SESSION];
/// The flags of `jsonl`.
pub const JSONL: &[Flag] = &[PROJECT_ROOT, ROOT, SOURCE, SESSION];
/// The flags of `tools`.
pub const TOOLS_COMMAND: &[Flag] = &[JSON, PROFILE];
/// The flags of `doctor`.
pub const DOCTOR: &[Flag] = &[PROJECT_ROOT];

/// The fuel of one did-you-mean search.
const DYM_FUEL: u64 = 100_000;

/// Gives the names of `names` that are close to `query`, best first.
pub fn closest<'a>(query: &str, names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut fuel = Fuel::new(DYM_FUEL);
    did_you_mean(query, names, &mut fuel)
        .into_iter()
        .map(|s| s.name)
        .collect()
}

/// Gives the error of a flag value that is not valid.
pub fn bad_value(flag: Flag, value: &str, expected: &str) -> UsageError {
    UsageError::new(&format!(
        "The value {value:?} of the flag {} is not valid. Use {expected}.",
        flag.name
    ))
}

/// Gives the error of an extra argument.
pub fn extra(arg: &str) -> UsageError {
    UsageError::new(&format!("The argument {arg} is not expected."))
}

/// The flag values and the positional arguments of one command.
#[derive(Debug, Default)]
pub struct Scan {
    values: BTreeMap<&'static str, Vec<String>>,
    /// The arguments that are not flags, in order.
    pub positional: Vec<String>,
}

impl Scan {
    /// Tells if the command line has `flag`.
    pub fn has(&self, flag: Flag) -> bool {
        self.values.contains_key(flag.name)
    }

    /// Gives the value of `flag`, or `None`.
    pub fn one(&self, flag: Flag) -> Option<&str> {
        self.values
            .get(flag.name)
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    /// Gives all values of `flag` in order.
    pub fn all(&self, flag: Flag) -> Vec<String> {
        self.values.get(flag.name).cloned().unwrap_or_default()
    }

    /// Gives an error when the command line has a positional argument.
    pub fn no_positional(&self) -> Result<(), UsageError> {
        self.positional
            .first()
            .map_or(Ok(()), |arg| Err(extra(arg)))
    }
}

/// Reads the flags `flags` of `command` from `args`.
pub fn scan(command: &str, args: &[String], flags: &[Flag]) -> Result<Scan, UsageError> {
    let mut out = Scan::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg.len() < 2 || !arg.starts_with('-') {
            out.positional.push(arg.clone());
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (arg.as_str(), None),
        };
        let Some(flag) = flags.iter().find(|f| f.name == name) else {
            return Err(UsageError {
                message: format!("The flag {name} is not known for the command {command}."),
                candidates: closest(name, flags.iter().map(|f| f.name)),
            });
        };
        let value = match (flag.value, inline) {
            (true, Some(value)) => value,
            (true, None) => rest
                .next()
                .cloned()
                .ok_or_else(|| UsageError::new(&format!("The flag {name} needs a value.")))?,
            (false, None) => String::new(),
            (false, Some(_)) => {
                return Err(UsageError::new(&format!("The flag {name} takes no value.")));
            }
        };
        let values = out.values.entry(flag.name).or_default();
        if !flag.repeat && !values.is_empty() {
            return Err(UsageError::new(&format!(
                "The flag {name} can occur only once."
            )));
        }
        values.push(value);
    }
    Ok(out)
}

/// Gives the value of `--profile`, or `None`.
pub fn profile(scan: &Scan) -> Result<Option<Profile>, UsageError> {
    scan.one(PROFILE)
        .map(|text| {
            parse_profile(text).ok_or_else(|| bad_value(PROFILE, text, "full, readonly or mini"))
        })
        .transpose()
}

/// Gives the tool allowlist of `--tools`, or `None`.
fn tools(scan: &Scan) -> Result<Option<BTreeSet<String>>, UsageError> {
    scan.one(TOOLS)
        .map(|text| {
            let names: BTreeSet<String> = text
                .split(',')
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(str::to_owned)
                .collect();
            if names.is_empty() {
                Err(bad_value(TOOLS, text, "a list of tool names such as a,b"))
            } else {
                Ok(names)
            }
        })
        .transpose()
}

/// Gives the session flags of a scan.
pub fn session(scan: &Scan) -> Result<SessionFlags, UsageError> {
    let source = scan
        .one(SOURCE)
        .map(|text| Source::parse(text).ok_or_else(|| bad_value(SOURCE, text, "agent or user")))
        .transpose()?
        .unwrap_or_default();
    Ok(SessionFlags {
        project_root: scan.one(PROJECT_ROOT).map(PathBuf::from),
        roots: scan.all(ROOT).into_iter().map(PathBuf::from).collect(),
        profile: profile(scan)?,
        tools: tools(scan)?,
        read_only: scan.has(READ_ONLY),
        open: scan.all(OPEN),
        break_lock: scan.has(BREAK_LOCK),
        source,
        session: scan.one(SESSION).map(str::to_owned),
    })
}
