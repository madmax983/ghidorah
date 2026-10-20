//! The single-writer lock of a project (design Section 3.10, ADR-0022).
//!
//! The lock file holds `{"boot_id":..,"pid":..,"start_time":..}`. The start time is field 22
//! of `/proc/<pid>/stat` (clock ticks after the boot). The boot ID is
//! `/proc/sys/kernel/random/boot_id`.
//!
//! A write open writes its owner to a temporary file of its own and syncs it. Then
//! [`Fs::link_new`] gives the file the name `project.lock`. The link fails when the lock
//! exists. So a lock file always holds its owner, and two processes never both take a lock.
//!
//! | Lock file | Owner process | Result |
//! |---|---|---|
//! | absent | - | the open takes the lock |
//! | present | alive: same boot ID, same start time | [`LockError::Held`]: `PROJECT_LOCKED` |
//! | present | not alive | [`LockError::Stale`], or a new lock with `--break-lock` |
//! | present, no owner that parses | unknown | [`LockError::Unknown`], or a new lock with `--break-lock` |
//!
//! A read-only open takes no lock. All file reads go through [`Fs`], so tests can give the
//! process files of their own.

#[cfg(test)]
mod tests;

use std::fmt;
use std::path::{Path, PathBuf};

use ghidorah_json::Value;

use crate::fs::{Fs, FsError, create_temp};

/// The file name of the lock in a project directory.
pub const LOCK_FILE: &str = "project.lock";

/// The start of the name of a temporary lock file.
pub const LOCK_TMP: &str = "project.lock.tmp";

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
    /// The lock file holds no owner that parses. An unknown process can hold it, so only
    /// `--break-lock` replaces the lock.
    Unknown,
    /// The owner of the lock is not alive. Only `--break-lock` replaces the lock.
    Stale(LockInfo),
    /// A file operation failed.
    Fs(FsError),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held(owner) => write!(f, "The process {owner} holds the project lock."),
            Self::Unknown => f.write_str(
                "The project lock has no owner that parses. Use --break-lock when no process uses the project.",
            ),
            Self::Stale(owner) => {
                write!(f, "The project lock of {owner} is stale. Use --break-lock.")
            }
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
    let rest = text.get(text.rfind(')')?.checked_add(1)?..)?;
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

/// Tells if no process has the ID `pid`: its file `/proc/<pid>/stat` does not exist. Another
/// read error keeps the process alive.
///
/// A temporary file name holds only the process ID, so the test cannot see a reused ID. The
/// file of a dead process with a reused ID stays.
pub fn pid_dead(fs: &mut dyn Fs, pid: u32) -> bool {
    fs.read(Path::new(&format!("/proc/{pid}/stat")))
        .is_err_and(|e| e.is_not_found())
}

/// Takes the lock of the project directory `dir` for `me`.
///
/// # Errors
///
/// Returns [`LockError::Held`] when a live process holds the lock. When `break_lock` is
/// `false`, a lock of a process that is not alive gives [`LockError::Stale`], and a lock with
/// no owner that parses gives [`LockError::Unknown`]. A failed file operation gives
/// [`LockError::Fs`].
pub fn acquire(
    fs: &mut dyn Fs,
    dir: &Path,
    me: &LockInfo,
    break_lock: bool,
) -> Result<(), LockError> {
    let file = path(dir);
    if publish(fs, dir, &file, me)? {
        return Ok(());
    }
    match read_owner(fs, &file) {
        Some(owner) if is_alive(fs, &owner) => return Err(LockError::Held(owner)),
        Some(owner) if !break_lock => return Err(LockError::Stale(owner)),
        None if !break_lock => return Err(LockError::Unknown),
        _ => {}
    }
    match fs.remove(&file) {
        Ok(()) | Err(FsError::NotFound(_)) => {}
        Err(e) => return Err(e.into()),
    }
    if publish(fs, dir, &file, me)? {
        return Ok(());
    }
    // Another process took the lock after the remove.
    Err(read_owner(fs, &file).map_or(LockError::Unknown, LockError::Held))
}

/// Writes the owner `me` to a new temporary file, syncs it and links it to the lock file.
/// Gives `false` when the lock file exists. The temporary file goes in all cases.
fn publish(fs: &mut dyn Fs, dir: &Path, file: &Path, me: &LockInfo) -> Result<bool, LockError> {
    let tmp = create_temp(fs, &dir.join(LOCK_TMP))?;
    let text = ghidorah_json::write(&me.to_json());
    let linked = fs
        .write_all(&tmp, text.as_bytes())
        .and_then(|()| fs.sync_file(&tmp))
        .and_then(|()| fs.link_new(&tmp, file));
    // The lock file keeps its data after the remove of the second name. A failed remove
    // leaves a file that no process reads.
    let _ = fs.remove(&tmp);
    match linked {
        Ok(()) => Ok(true),
        Err(FsError::Exists(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Reads the owner of a lock file. A file that does not parse gives `None`.
fn read_owner(fs: &mut dyn Fs, file: &Path) -> Option<LockInfo> {
    let bytes = fs.read(file).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let value = ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT).ok()?;
    LockInfo::from_json(&value)
}

/// Removes the lock of `dir` when it names `me`, and syncs the directory. Another owner keeps
/// its lock.
///
/// # Errors
///
/// Returns the [`FsError`] of a failed remove.
pub fn release(fs: &mut dyn Fs, dir: &Path, me: &LockInfo) -> Result<(), FsError> {
    let file = path(dir);
    if read_owner(fs, &file).as_ref() == Some(me) {
        fs.remove(&file)?;
        fs.sync_dir(dir)?;
    }
    Ok(())
}
