//! Child processes for xtask commands.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::process::{Command, Stdio};

use crate::Error;

/// The captured result of a child process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The exit code, or `None` when a signal stopped the process.
    pub code: Option<i32>,
    /// The standard output as UTF-8 text (lossy).
    pub stdout: String,
    /// The standard error as UTF-8 text (lossy).
    pub stderr: String,
}

impl Output {
    /// Tells if the process exited with code 0.
    #[must_use]
    pub const fn ok(&self) -> bool {
        matches!(self.code, Some(0))
    }
}

/// Gives the cargo program: the `CARGO` variable that cargo sets, else `cargo`.
#[must_use]
pub fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

/// Gives a cargo command with the given arguments.
#[must_use]
pub fn cargo_cmd(args: &[&str]) -> Command {
    let mut cmd = Command::new(cargo());
    cmd.args(args);
    cmd
}

/// Gives the program and the arguments of a command as one line.
#[must_use]
pub fn describe(cmd: &Command) -> String {
    let mut text = cmd.get_program().to_string_lossy().into_owned();
    for arg in cmd.get_args() {
        let _ = write!(text, " {}", arg.to_string_lossy());
    }
    text
}

/// Gives the last `count` lines of a text.
#[must_use]
pub fn tail(text: &str, count: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(count);
    lines.get(start..).unwrap_or_default().join("\n")
}

/// Runs a command to its end and captures its output.
///
/// A non-zero exit code is not an error here. Use [`Output::ok`].
///
/// # Errors
///
/// Returns [`Error::Command`] when the process does not start.
pub fn run(cmd: &mut Command) -> Result<Output, Error> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::Command {
            argv: describe(cmd),
            code: None,
            stderr: e.to_string(),
        })?;
    Ok(Output {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Runs a command and requires exit code 0.
///
/// # Errors
///
/// Returns [`Error::Command`] when the process does not start or exits with another code.
pub fn run_ok(cmd: &mut Command) -> Result<Output, Error> {
    let out = run(cmd)?;
    if out.ok() {
        Ok(out)
    } else {
        Err(Error::Command {
            argv: describe(cmd),
            code: out.code,
            stderr: tail(&out.stderr, 20),
        })
    }
}
