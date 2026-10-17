//! The path roots of `binary_load` (design Section 10.16, ADR-0022).
//!
//! The server reads a file only under its configured roots. The check has these steps:
//!
//! 1. A relative path starts at the first root.
//! 2. The lexical form of the path, with `.` and `..` resolved, must stay under a root.
//! 3. `canonicalize` resolves the symlinks. The canonical path must also stay under a root.
//! 4. The path must name a regular file of at most the size limit.
//!
//! A path that leaves the roots gives `PATH_OUTSIDE_ROOT` with `details.roots`. The error
//! never shows an absolute path: each root shows its relative name. A file that does not exist
//! or does not read gives `FILE_UNREADABLE`.

use std::fmt;
use std::path::{Path, PathBuf};

use ghidorah_json::Value;

use crate::errors::ToolError;

/// The largest number of roots.
pub const MAX_ROOTS: usize = 64;

/// One root: a canonical directory and its relative name for output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    /// The name in output: the text of a relative root, or the last part of an absolute root.
    pub name: String,
    /// The canonical directory.
    pub path: PathBuf,
}

/// The roots of one server.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Roots {
    roots: Vec<Root>,
}

/// The error of [`Roots::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootError {
    /// The list holds no root.
    Empty,
    /// The list holds more than [`MAX_ROOTS`] roots.
    TooMany {
        /// The number of roots.
        count: usize,
    },
    /// A root is not a directory, or `canonicalize` fails for it.
    NotADirectory {
        /// The root text as the caller gave it.
        root: String,
    },
}

impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("The root list is empty. Give at least one root."),
            Self::TooMany { count } => write!(
                f,
                "The root list has {count} roots. The limit is {MAX_ROOTS} roots."
            ),
            Self::NotADirectory { root } => {
                write!(
                    f,
                    "The root {root} is not a directory that the process can read."
                )
            }
        }
    }
}

impl std::error::Error for RootError {}

/// The file that [`Roots::read`] gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFile {
    /// The file name: the last part of the path.
    pub file_name: String,
    /// The bytes.
    pub bytes: Vec<u8>,
}

impl Roots {
    /// Makes the roots of `dirs`, in this order. A relative directory starts at `base`.
    ///
    /// # Errors
    ///
    /// Returns [`RootError`] for an empty list, too many roots or a root that is not a
    /// directory.
    pub fn new(base: &Path, dirs: &[PathBuf]) -> Result<Self, RootError> {
        let _ = (base, dirs);
        Err(RootError::Empty)
    }

    /// Gives the roots in order.
    #[must_use]
    pub fn roots(&self) -> &[Root] {
        &self.roots
    }

    /// Gives the relative names of the roots as a JSON array for `details.roots`.
    #[must_use]
    pub fn names(&self) -> Value {
        Value::Array(Vec::new())
    }

    /// Gives the canonical path of `path` when the path stays under a root.
    ///
    /// # Errors
    ///
    /// Returns `PATH_OUTSIDE_ROOT` when the path leaves the roots and `FILE_UNREADABLE` when
    /// `canonicalize` fails.
    pub fn check(&self, path: &str) -> Result<PathBuf, ToolError> {
        let _ = path;
        Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
    }

    /// Reads the file at `path` with the checks of the module docs.
    ///
    /// # Errors
    ///
    /// Returns `PATH_OUTSIDE_ROOT`, `FILE_UNREADABLE` for a missing, unreadable or special
    /// file, and `LIMIT_EXCEEDED` for a file above `max_bytes` bytes.
    pub fn read(&self, path: &str, max_bytes: u64) -> Result<ReadFile, ToolError> {
        let _ = (path, max_bytes);
        Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
    }
}
