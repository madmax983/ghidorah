//! The error type of all xtask commands.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// A failure that stops an xtask command.
///
/// A gate violation is not an error. Gates return [`crate::Finding`] values.
#[derive(Debug)]
pub enum Error {
    /// A file operation failed.
    Io {
        /// The file or directory of the operation.
        path: PathBuf,
        /// The cause from the operating system.
        source: io::Error,
    },
    /// A child process did not start, or it failed.
    Command {
        /// The program and its arguments.
        argv: String,
        /// The exit code, or `None` when no code is available.
        code: Option<i32>,
        /// The last lines of the error output.
        stderr: String,
    },
    /// An input file or a command output has a bad form.
    Data {
        /// The file or the command that gave the data.
        origin: String,
        /// What is wrong.
        message: String,
    },
    /// The command line is not valid.
    Usage(String),
}

impl Error {
    /// Makes an [`Error::Io`] value.
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Makes an [`Error::Data`] value.
    pub fn data(origin: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Data {
            origin: origin.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Command { argv, code, stderr } => match code {
                Some(c) => write!(f, "command `{argv}` failed with exit code {c}: {stderr}"),
                None => write!(f, "command `{argv}` failed: {stderr}"),
            },
            Self::Data { origin, message } => write!(f, "{origin}: {message}"),
            Self::Usage(text) => write!(f, "usage: {text}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
