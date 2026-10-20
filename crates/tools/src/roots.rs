//! The path roots of `binary_load` (design Section 10.16, ADR-0022).
//!
//! The server reads a file only under its configured roots. The check has these steps:
//!
//! 1. A relative path starts at the first root.
//! 2. The lexical form of the path, with `.` and `..` resolved, must stay under a root.
//! 3. `canonicalize` resolves the symlinks. The canonical path must also stay under a root.
//! 4. The path must name a regular file of at most the size limit. The type check runs before
//!    the open and again on the open file. The open never waits for the writer of a FIFO.
//!
//! A path that leaves the roots gives `PATH_OUTSIDE_ROOT` with `details.roots`. The error
//! never shows an absolute path: each root shows its relative name. A file that does not exist
//! or does not read gives `FILE_UNREADABLE`.

use std::fmt;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use ghidorah_base::ErrorCode;
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
        if dirs.is_empty() {
            return Err(RootError::Empty);
        }
        if dirs.len() > MAX_ROOTS {
            return Err(RootError::TooMany { count: dirs.len() });
        }
        let mut roots = Vec::with_capacity(dirs.len());
        for dir in dirs {
            let joined = if dir.is_absolute() {
                dir.clone()
            } else {
                base.join(dir)
            };
            let path = std::fs::canonicalize(&joined)
                .ok()
                .filter(|p| p.is_dir())
                .ok_or_else(|| RootError::NotADirectory {
                    root: dir.display().to_string(),
                })?;
            let name = if dir.is_absolute() {
                path.file_name()
                    .map_or_else(|| "/".to_owned(), |n| n.to_string_lossy().into_owned())
            } else {
                dir.display().to_string()
            };
            roots.push(Root { name, path });
        }
        Ok(Self { roots })
    }

    /// Gives the roots in order.
    #[must_use]
    pub fn roots(&self) -> &[Root] {
        &self.roots
    }

    /// Gives the relative names of the roots as a JSON array for `details.roots`.
    #[must_use]
    pub fn names(&self) -> Value {
        Value::Array(
            self.roots
                .iter()
                .map(|r| Value::from(r.name.as_str()))
                .collect(),
        )
    }

    /// Tells if `path` is a root or a path under a root.
    fn holds(&self, path: &Path) -> bool {
        self.roots.iter().any(|r| path.starts_with(&r.path))
    }

    /// Gives the `PATH_OUTSIDE_ROOT` error with the root names.
    fn outside(&self) -> ToolError {
        ToolError::new(ErrorCode::PathOutsideRoot).detail("roots", self.names())
    }

    /// Gives the canonical path of `path` when the path stays under a root.
    ///
    /// # Errors
    ///
    /// Returns `PATH_OUTSIDE_ROOT` when the path leaves the roots and `FILE_UNREADABLE` when
    /// `canonicalize` fails.
    pub fn check(&self, path: &str) -> Result<PathBuf, ToolError> {
        let first = self.roots.first().ok_or_else(|| self.outside())?;
        let raw = Path::new(path);
        let joined = if raw.is_absolute() {
            raw.to_path_buf()
        } else {
            first.path.join(raw)
        };
        if !self.holds(&lexical(&joined)) {
            return Err(self.outside());
        }
        let canonical = std::fs::canonicalize(&joined)
            .map_err(|_| ToolError::new(ErrorCode::FileUnreadable))?;
        if self.holds(&canonical) {
            Ok(canonical)
        } else {
            Err(self.outside())
        }
    }

    /// Reads the file at `path` with the checks of the module docs.
    ///
    /// # Errors
    ///
    /// Returns `PATH_OUTSIDE_ROOT`, `FILE_UNREADABLE` for a missing, unreadable or special
    /// file, and `LIMIT_EXCEEDED` for a file above `max_bytes` bytes.
    pub fn read(&self, path: &str, max_bytes: u64) -> Result<ReadFile, ToolError> {
        let canonical = self.check(path)?;
        let unreadable = |_| ToolError::new(ErrorCode::FileUnreadable);
        // The open of a FIFO blocks until a writer comes. So the type check comes first.
        if !std::fs::metadata(&canonical).map_err(unreadable)?.is_file() {
            return Err(ToolError::new(ErrorCode::FileUnreadable));
        }
        let file = open_no_block(&canonical).map_err(unreadable)?;
        // The second check closes the race: the path can change after the first check.
        let meta = file.metadata().map_err(unreadable)?;
        if !meta.is_file() {
            return Err(ToolError::new(ErrorCode::FileUnreadable));
        }
        let too_large = |size: u64| {
            ToolError::new(ErrorCode::LimitExceeded)
                .detail("size", Value::from(size))
                .detail("limit", Value::from(max_bytes))
        };
        if meta.len() > max_bytes {
            return Err(too_large(meta.len()));
        }
        let mut bytes = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(unreadable)?;
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if size > max_bytes {
            return Err(too_large(size));
        }
        let file_name = canonical
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(ReadFile { file_name, bytes })
    }
}

/// The `O_NONBLOCK` flag of `open` on Linux and Android, for most CPU types.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "sparc",
        target_arch = "sparc64"
    ))
))]
const O_NONBLOCK: i32 = 0o4000;

/// The `O_NONBLOCK` flag of `open` on Linux for MIPS.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "mips", target_arch = "mips64")
))]
const O_NONBLOCK: i32 = 0x80;

/// The `O_NONBLOCK` flag of `open` on Linux for SPARC.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(target_arch = "sparc", target_arch = "sparc64")
))]
const O_NONBLOCK: i32 = 0x4000;

/// The `O_NONBLOCK` flag of `open` on macOS and the BSD systems.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const O_NONBLOCK: i32 = 0x4;

/// No flag on other Unix systems. The type check before the open stays.
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))
))]
const O_NONBLOCK: i32 = 0;

/// Opens `path` to read. On Unix the open uses `O_NONBLOCK`, so a special file never blocks it.
fn open_no_block(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(O_NONBLOCK);
    }
    options.open(path)
}

/// Gives the lexical form of `path`: `.` parts go, and each `..` drops the part before it.
///
/// A `..` at the top stays at the top, as the file system does.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                out.push(part.as_os_str());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
