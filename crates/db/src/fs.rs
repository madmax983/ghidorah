//! The file-system seam of the persistence modules (design Section 3.10).
//!
//! Each project write goes through the [`Fs`] trait. Production uses [`RealFs`]. The tests use
//! a simulated file system with an operation log and a crash point
//! (`crates/db/tests/common/fs_sim.rs`).
//!
//! | Operation | Use |
//! |---|---|
//! | [`Fs::create_new`] | a new empty file. It fails when the path exists. |
//! | [`Fs::append`] | one journal line |
//! | [`Fs::write_all`] | the content of a file that exists |
//! | [`Fs::sync_file`] | makes the data of a file durable |
//! | [`Fs::rename`] | puts a temporary file in place |
//! | [`Fs::sync_dir`] | makes the names of a directory durable |
//! | [`Fs::remove`] | removes a file |
//! | [`Fs::read`] | reads a file |
//!
//! The other operations make directories, set the mode 0444, list a directory and test a
//! path. A commit is [`Fs::append`] and then [`Fs::sync_file`].

#[cfg(test)]
mod tests;

use std::fmt;
use std::path::{Path, PathBuf};

/// The error of a file-system operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    /// The path does not exist.
    NotFound(PathBuf),
    /// The path exists, and the operation needs a new path.
    Exists(PathBuf),
    /// The operating system refused the operation.
    Io {
        /// The operation, for example `append`.
        op: &'static str,
        /// The path.
        path: PathBuf,
        /// The text of the operating system error.
        message: String,
    },
    /// A simulated crash stopped the file system. Each later operation fails.
    Stopped,
}

impl FsError {
    /// Tells if the error is [`FsError::NotFound`].
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    /// Makes the error of a failed `std::io` operation.
    fn io(op: &'static str, path: &Path, e: &std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => Self::NotFound(path.to_path_buf()),
            std::io::ErrorKind::AlreadyExists => Self::Exists(path.to_path_buf()),
            _ => Self::Io {
                op,
                path: path.to_path_buf(),
                message: e.to_string(),
            },
        }
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(p) => write!(f, "The path {} does not exist.", p.display()),
            Self::Exists(p) => write!(f, "The path {} exists already.", p.display()),
            Self::Io { op, path, message } => {
                write!(
                    f,
                    "The operation {op} on {} fails: {message}",
                    path.display()
                )
            }
            Self::Stopped => f.write_str("A simulated crash stopped the file system."),
        }
    }
}

impl std::error::Error for FsError {}

/// The file operations of the persistence modules.
///
/// A path is absolute or relative to the current directory of the process. The persistence
/// modules use the paths of one project directory and the process files under `/proc`.
pub trait Fs: Send {
    /// Makes a directory and its missing parents.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::Io`] when the directory cannot exist.
    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError>;

    /// Makes a new empty file.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::Exists`] when the path exists.
    fn create_new(&mut self, path: &Path) -> Result<(), FsError>;

    /// Adds `bytes` at the end of a file that exists.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the file does not exist.
    fn append(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError>;

    /// Puts `bytes` in place of the content of a file that exists.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the file does not exist.
    fn write_all(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError>;

    /// Makes the data of a file durable.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the file does not exist.
    fn sync_file(&mut self, path: &Path) -> Result<(), FsError>;

    /// Moves a file to a new name. A file at the new name goes.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the source does not exist.
    fn rename(&mut self, from: &Path, to: &Path) -> Result<(), FsError>;

    /// Makes the names of a directory durable.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the directory does not exist.
    fn sync_dir(&mut self, path: &Path) -> Result<(), FsError>;

    /// Removes a file.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the file does not exist.
    fn remove(&mut self, path: &Path) -> Result<(), FsError>;

    /// Reads a file.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the file does not exist.
    fn read(&mut self, path: &Path) -> Result<Vec<u8>, FsError>;

    /// Sets the mode of a file to 0444: read for all, no write and no exec.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the file does not exist.
    fn set_read_only(&mut self, path: &Path) -> Result<(), FsError>;

    /// Gives the names of the entries of a directory in name order.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the directory does not exist.
    fn list(&mut self, dir: &Path) -> Result<Vec<String>, FsError>;

    /// Tells if a file or a directory exists at the path.
    fn exists(&mut self, path: &Path) -> bool;

    /// Gives a second handle on the same file system.
    fn boxed(&self) -> Box<dyn Fs>;
}

/// The file system of the operating system.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RealFs;

impl Fs for RealFs {
    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        std::fs::create_dir_all(path).map_err(|e| FsError::io("create_dir_all", path, &e))
    }

    fn create_new(&mut self, path: &Path) -> Result<(), FsError> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map(drop)
            .map_err(|e| FsError::io("create_new", path, &e))
    }

    fn append(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| FsError::io("append", path, &e))?;
        file.write_all(bytes)
            .map_err(|e| FsError::io("append", path, &e))
    }

    fn write_all(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| FsError::io("write_all", path, &e))?;
        file.write_all(bytes)
            .map_err(|e| FsError::io("write_all", path, &e))
    }

    fn sync_file(&mut self, path: &Path) -> Result<(), FsError> {
        std::fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| FsError::io("sync_file", path, &e))
    }

    fn rename(&mut self, from: &Path, to: &Path) -> Result<(), FsError> {
        std::fs::rename(from, to).map_err(|e| FsError::io("rename", from, &e))
    }

    fn sync_dir(&mut self, path: &Path) -> Result<(), FsError> {
        std::fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| FsError::io("sync_dir", path, &e))
    }

    fn remove(&mut self, path: &Path) -> Result<(), FsError> {
        std::fs::remove_file(path).map_err(|e| FsError::io("remove", path, &e))
    }

    fn read(&mut self, path: &Path) -> Result<Vec<u8>, FsError> {
        std::fs::read(path).map_err(|e| FsError::io("read", path, &e))
    }

    fn set_read_only(&mut self, path: &Path) -> Result<(), FsError> {
        let mut perms = std::fs::metadata(path)
            .map_err(|e| FsError::io("set_read_only", path, &e))?
            .permissions();
        set_mode_0444(&mut perms);
        std::fs::set_permissions(path, perms).map_err(|e| FsError::io("set_read_only", path, &e))
    }

    fn list(&mut self, dir: &Path) -> Result<Vec<String>, FsError> {
        let entries = std::fs::read_dir(dir).map_err(|e| FsError::io("list", dir, &e))?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| FsError::io("list", dir, &e))?;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    fn exists(&mut self, path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn boxed(&self) -> Box<dyn Fs> {
        Box::new(*self)
    }
}

/// Sets the permission bits to 0444.
#[cfg(unix)]
fn set_mode_0444(perms: &mut std::fs::Permissions) {
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o444);
}

/// Sets the read-only flag. Other systems have no mode bits.
#[cfg(not(unix))]
fn set_mode_0444(perms: &mut std::fs::Permissions) {
    perms.set_readonly(true);
}
