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
//! | [`Fs::write_from`] | the content of a file that exists, one piece at a time: a snapshot |
//! | [`Fs::truncate`] | cuts a journal back after a failed append |
//! | [`Fs::sync_file`] | makes the data of a file durable |
//! | [`Fs::rename`] | puts a temporary file in place |
//! | [`Fs::link_new`] | puts a temporary file at a new name. It fails when the name exists. |
//! | [`Fs::sync_dir`] | makes the names of a directory durable |
//! | [`Fs::remove`] | removes a file |
//! | [`Fs::read`] | reads a file |
//! | [`Fs::modified`] | the time of the last change of a file |
//!
//! The other operations make directories, set the mode 0444, list a directory and test a
//! path. A commit is [`Fs::append`] and then [`Fs::sync_file`].
//!
//! A temporary file has a name of this process: `<base>.<pid>.<n>`. `n` counts up in the
//! process. So two processes never use the same temporary file. A process that stops between
//! the create and the rename leaves its temporary file. A write open removes these files from
//! the project directory and its `bin` and `crash` directories with `remove_dead_temps`. It
//! keeps the temporary files of live processes.
//!
//! The process test reads only the local `/proc`. A process on another host or in another PID
//! namespace is not there. So the sweep also keeps each file that changed in the last
//! [`TEMP_GRACE`], and each file with no change time. The caller gives the time now in the
//! clock of the file system.
//!
//! [`RealFs`] never writes through a symbolic link. `create_new`, `append`, `write_all` and
//! `truncate` give [`FsError::WrongKind`] for a path that is not a regular file.

#[cfg(test)]
mod tests;

mod temp;

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[cfg(test)]
pub(crate) use temp::SWEEP_MAX;
pub use temp::TEMP_GRACE;
pub(crate) use temp::{
    create_temp, remove_dead_temps, remove_dead_temps_by, replace_file, replace_file_from, temp_pid,
};

/// The content source of [`Fs::write_from`]. It gives each piece of the content to its
/// argument, in order. An error text stops the write.
pub type Fill<'a> = dyn FnMut(&mut dyn FnMut(&[u8])) -> Result<(), String> + 'a;

/// The size of the write buffer of [`RealFs::write_from`].
const WRITE_BUF: usize = 1 << 20;

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
    /// The entry at the path is a symbolic link, or it is not of the kind that the operation
    /// needs. The operation refuses it.
    WrongKind(PathBuf),
    /// A simulated crash stopped the file system. Each later operation fails.
    Stopped,
}

/// The kind of an entry at a path. The test does not follow a symbolic link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link or another kind of entry.
    Other,
}

impl FsError {
    /// Tells if the error is [`FsError::NotFound`].
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    /// Makes the error of a failed content source of [`Fs::write_from`].
    fn fill(path: &Path, message: String) -> Self {
        Self::Io {
            op: "write_all",
            path: path.to_path_buf(),
            message,
        }
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
            Self::WrongKind(p) => write!(
                f,
                "The path {} is a symbolic link or an entry of the wrong kind.",
                p.display()
            ),
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
    /// Makes a directory and its missing parents. [`RealFs`] gives each new directory the mode
    /// 0700.
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

    /// Puts the bytes that `fill` gives, one piece at a time, in place of the content of a
    /// file that exists. So no copy of the whole content is necessary.
    ///
    /// The default collects the pieces and calls [`Fs::write_all`] one time. So the
    /// operation log of a simulated file system holds one `write_all`.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the file does not exist. A failed `fill` gives
    /// [`FsError::Io`] with the operation `write_all` and the text of `fill`.
    fn write_from(&mut self, path: &Path, fill: &mut Fill<'_>) -> Result<(), FsError> {
        let mut bytes = Vec::new();
        fill(&mut |piece| bytes.extend_from_slice(piece)).map_err(|m| FsError::fill(path, m))?;
        self.write_all(path, &bytes)
    }

    /// Cuts a file that exists to `len` bytes and makes the result durable.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::NotFound`] when the file does not exist.
    fn truncate(&mut self, path: &Path, len: u64) -> Result<(), FsError>;

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

    /// Gives the file `src` a second name `dst`: a hard link. The operation is atomic, and it
    /// never replaces an entry at `dst`.
    ///
    /// # Errors
    ///
    /// Returns [`FsError::Exists`] when `dst` exists, and [`FsError::NotFound`] when `src`
    /// does not exist.
    fn link_new(&mut self, src: &Path, dst: &Path) -> Result<(), FsError>;

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

    /// Gives the kind of the entry at the path, or `None` when no entry is there. The test does
    /// not follow a symbolic link.
    fn kind(&mut self, path: &Path) -> Option<EntryKind>;

    /// Gives the time of the last change of the entry at the path, in the clock of the file
    /// system. No entry, or a file system with no change time, gives `None`. The query does not
    /// follow a symbolic link.
    fn modified(&mut self, path: &Path) -> Option<SystemTime>;

    /// Gives a second handle on the same file system.
    fn boxed(&self) -> Box<dyn Fs>;
}

/// The file system of the operating system.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RealFs;

impl Fs for RealFs {
    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        private_dirs(&mut builder);
        builder
            .create(path)
            .map_err(|e| FsError::io("create_dir_all", path, &e))
    }

    fn create_new(&mut self, path: &Path) -> Result<(), FsError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        open_regular("create_new", path, &options).map(drop)
    }

    fn append(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.append(true);
        let mut file = open_regular("append", path, &options)?;
        file.write_all(bytes)
            .map_err(|e| FsError::io("append", path, &e))
    }

    fn write_all(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        use std::io::Write;
        // The open does not cut the file. The cut comes after the check of the open file.
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        let mut file = open_regular("write_all", path, &options)?;
        file.set_len(0)
            .and_then(|()| file.write_all(bytes))
            .map_err(|e| FsError::io("write_all", path, &e))
    }

    fn write_from(&mut self, path: &Path, fill: &mut Fill<'_>) -> Result<(), FsError> {
        use std::io::Write;
        let fail = |e: &std::io::Error| FsError::io("write_all", path, e);
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        let target = open_regular("write_all", path, &options)?;
        target.set_len(0).map_err(|e| fail(&e))?;
        let mut out = std::io::BufWriter::with_capacity(WRITE_BUF, target);
        let mut failed: Option<std::io::Error> = None;
        let filled = fill(&mut |piece| {
            if failed.is_none()
                && let Err(e) = out.write_all(piece)
            {
                failed = Some(e);
            }
        });
        if let Some(e) = failed {
            return Err(fail(&e));
        }
        filled.map_err(|m| FsError::fill(path, m))?;
        out.flush().map_err(|e| fail(&e))
    }

    fn truncate(&mut self, path: &Path, len: u64) -> Result<(), FsError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        let file = open_regular("truncate", path, &options)?;
        file.set_len(len)
            .and_then(|()| file.sync_all())
            .map_err(|e| FsError::io("truncate", path, &e))
    }

    fn sync_file(&mut self, path: &Path) -> Result<(), FsError> {
        std::fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|e| FsError::io("sync_file", path, &e))
    }

    fn rename(&mut self, from: &Path, to: &Path) -> Result<(), FsError> {
        std::fs::rename(from, to).map_err(|e| FsError::io("rename", from, &e))
    }

    fn link_new(&mut self, src: &Path, dst: &Path) -> Result<(), FsError> {
        std::fs::hard_link(src, dst).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                FsError::Exists(dst.to_path_buf())
            } else {
                FsError::io("link_new", src, &e)
            }
        })
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

    fn kind(&mut self, path: &Path) -> Option<EntryKind> {
        let kind = std::fs::symlink_metadata(path).ok()?.file_type();
        Some(if kind.is_file() {
            EntryKind::File
        } else if kind.is_dir() {
            EntryKind::Dir
        } else {
            EntryKind::Other
        })
    }

    fn modified(&mut self, path: &Path) -> Option<SystemTime> {
        std::fs::symlink_metadata(path).ok()?.modified().ok()
    }

    fn boxed(&self) -> Box<dyn Fs> {
        Box::new(*self)
    }
}

/// Opens a regular file for a write with `options`.
///
/// The open refuses a path that is a symbolic link or not a regular file. After the open, the
/// name must still give the open file: the same device and inode. So a link that goes in
/// place of the file during the open gives no write to another file.
fn open_regular(
    op: &'static str,
    path: &Path,
    options: &std::fs::OpenOptions,
) -> Result<std::fs::File, FsError> {
    let refuse = || FsError::WrongKind(path.to_path_buf());
    if let Ok(entry) = std::fs::symlink_metadata(path)
        && !entry.file_type().is_file()
    {
        return Err(refuse());
    }
    let file = options.open(path).map_err(|e| FsError::io(op, path, &e))?;
    let opened = file.metadata().map_err(|e| FsError::io(op, path, &e))?;
    let named = std::fs::symlink_metadata(path).map_err(|e| FsError::io(op, path, &e))?;
    if !named.file_type().is_file() || !same_file(&opened, &named) {
        return Err(refuse());
    }
    Ok(file)
}

/// Tells if two metadata records are of one file: the same device and inode.
#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Tells if the open file is a regular file. Other systems give no inode numbers.
#[cfg(not(unix))]
fn same_file(a: &std::fs::Metadata, _: &std::fs::Metadata) -> bool {
    a.is_file()
}

/// Gives each new directory the mode 0700: only the owner can read, write or search it.
#[cfg(unix)]
fn private_dirs(builder: &mut std::fs::DirBuilder) {
    use std::os::unix::fs::DirBuilderExt;
    builder.mode(0o700);
}

/// Keeps the default mode. Other systems have no mode bits.
#[cfg(not(unix))]
fn private_dirs(_: &mut std::fs::DirBuilder) {}

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
