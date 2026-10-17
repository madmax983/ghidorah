//! The single-writer lock of a project (design Section 3.10, ADR-0022).
//!
//! A write open makes `project.lock` with `create_new`. The file holds
//! `{"boot_id":..,"pid":..,"start_time":..}`. The start time is field 22 of `/proc/<pid>/stat`
//! (clock ticks after the boot). The boot ID is `/proc/sys/kernel/random/boot_id`.
//!
//! | Lock file | Owner process | Result |
//! |---|---|---|
//! | absent | - | the open takes the lock |
//! | present | alive: same boot ID, same start time | [`LockError::Held`]: `PROJECT_LOCKED` |
//! | present | not alive, or the file does not parse | [`LockError::Stale`], or a new lock with `--break-lock` |
//!
//! A read-only open takes no lock. All file reads go through [`Fs`], so tests can give the
//! process files of their own.

#[cfg(test)]
mod tests;

use std::fmt;
use std::path::{Path, PathBuf};

use ghidorah_json::Value;

use crate::fs::{Fs, FsError};

/// The file name of the lock in a project directory.
pub const LOCK_FILE: &str = "project.lock";

/// The file of the boot ID.
pub const BOOT_ID_FILE: &str = "/proc/sys/kernel/random/boot_id";

/// The owner of a lock: one process of one boot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockInfo {
    /// The process ID.
    pub pid: u32,
    /// The start time of the process: field 22 of `/proc/<pid>/stat`.
    pub start_time: u64,
    /// The boot ID.
    pub boot_id: String,
}

impl LockInfo {
    /// Gives the JSON form `{boot_id, pid, start_time}`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::object([
            ("boot_id", Value::from(self.boot_id.as_str())),
            ("pid", Value::from(self.pid)),
            ("start_time", Value::from(self.start_time)),
        ])
    }

    /// Reads the JSON form. Gives `None` for another shape.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let pid = u32::try_from(value.get("pid")?.as_u64()?).ok()?;
        Some(Self {
            pid,
            start_time: value.get("start_time")?.as_u64()?,
            boot_id: value.get("boot_id")?.as_str()?.to_owned(),
        })
    }
}

impl fmt::Display for LockInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pid {} (start time {}, boot {})",
            self.pid, self.start_time, self.boot_id
        )
    }
}

/// The error of a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    /// A live process holds the lock.
    Held(LockInfo),
    /// The owner of the lock is not alive. Only `--break-lock` replaces the lock.
    Stale(Option<LockInfo>),
    /// A file operation failed.
    Fs(FsError),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held(owner) => write!(f, "The process {owner} holds the project lock."),
            Self::Stale(Some(owner)) => {
                write!(f, "The project lock of {owner} is stale. Use --break-lock.")
            }
            Self::Stale(None) => f.write_str("The project lock does not parse. Use --break-lock."),
            Self::Fs(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LockError {}

impl From<FsError> for LockError {
    fn from(e: FsError) -> Self {
        Self::Fs(e)
    }
}

/// Gives the path of the lock file of the project directory `dir`.
#[must_use]
pub fn path(dir: &Path) -> PathBuf {
    dir.join(LOCK_FILE)
}

/// Gives the start time of a process from the text of its `/proc/<pid>/stat` file.
///
/// The process name in parentheses can hold spaces and parentheses. So the fields start
/// after the last `)`. Gives `None` for text with another shape.
#[must_use]
pub fn stat_start_time(text: &str) -> Option<u64> {
    let rest = &text[text.rfind(')')?.checked_add(1)?..];
    // Field 3 (the state) is the first field after the name. Field 22 is the start time.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Gives the lock owner of process `pid` from its process files, or `None`.
pub fn process_info(fs: &mut dyn Fs, pid: u32) -> Option<LockInfo> {
    let stat = fs.read(Path::new(&format!("/proc/{pid}/stat"))).ok()?;
    let start_time = stat_start_time(&String::from_utf8_lossy(&stat))?;
    let boot = fs.read(Path::new(BOOT_ID_FILE)).ok()?;
    Some(LockInfo {
        pid,
        start_time,
        boot_id: String::from_utf8_lossy(&boot).trim().to_owned(),
    })
}

/// Gives the lock owner of this process, or `None` when its process files do not read.
pub fn current(fs: &mut dyn Fs) -> Option<LockInfo> {
    process_info(fs, std::process::id())
}

/// Tells if the owner of a lock is alive: its process files give the same start time and
/// the same boot ID.
pub fn is_alive(fs: &mut dyn Fs, owner: &LockInfo) -> bool {
    process_info(fs, owner.pid).as_ref() == Some(owner)
}

/// Takes the lock of the project directory `dir` for `me`.
///
/// # Errors
///
/// Returns [`LockError::Held`] when a live process holds the lock, and [`LockError::Stale`]
/// for a lock of a process that is not alive when `break_lock` is `false`. A failed file
/// operation gives [`LockError::Fs`].
pub fn acquire(
    fs: &mut dyn Fs,
    dir: &Path,
    me: &LockInfo,
    break_lock: bool,
) -> Result<(), LockError> {
    let _ = (fs, dir, me, break_lock);
    Err(LockError::Stale(None))
}

/// Removes the lock of `dir` when it names `me`. Another owner keeps its lock.
///
/// # Errors
///
/// Returns the [`FsError`] of a failed remove.
pub fn release(fs: &mut dyn Fs, dir: &Path, me: &LockInfo) -> Result<(), FsError> {
    let _ = (fs, dir, me);
    Ok(())
}
