//! The temporary files of the project writes: the create, the replace and the sweep of the
//! files of dead processes (see the module doc of [`super`]).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use super::{EntryKind, Fs, FsError};

/// The counter of the temporary file names of this process.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// The maximum number of names that [`create_temp`] tries.
const TMP_TRIES: usize = 64;

/// The maximum number of directory entries that [`remove_dead_temps`] reads.
pub(crate) const SWEEP_MAX: usize = 4_096;

/// A temporary file of a dead process stays for this time after its last change.
pub const TEMP_GRACE: Duration = Duration::from_hours(1);

/// The maximum number of digits of a number in a temporary file name: the digits of
/// `u64::MAX`.
const MAX_DIGITS: usize = 20;

/// Makes a new empty temporary file of this process: `<base>.<pid>.<n>`.
///
/// A name that exists stays as it is, and the next `n` gets a try. Gives the path of the
/// new file.
///
/// # Errors
///
/// Returns the [`FsError`] of a failed `create_new`, or [`FsError::Exists`] after
/// [`TMP_TRIES`] names that exist.
pub(crate) fn create_temp(fs: &mut dyn Fs, base: &Path) -> Result<PathBuf, FsError> {
    let pid = std::process::id();
    let mut last = FsError::Exists(base.to_path_buf());
    for _ in 0..TMP_TRIES {
        let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut name = base.as_os_str().to_os_string();
        name.push(format!(".{pid}.{n}"));
        let tmp = PathBuf::from(name);
        match fs.create_new(&tmp) {
            Ok(()) => return Ok(tmp),
            Err(e @ FsError::Exists(_)) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Puts `bytes` at `path` through a temporary file of this process and a rename.
///
/// The operations are `create_new` of `<tmp>.<pid>.<n>`, `write_all`, `sync_file` and
/// `rename`. After a failure, the temporary file of this process goes. The caller syncs the
/// directory.
///
/// # Errors
///
/// Returns the [`FsError`] of the first failed operation.
pub(crate) fn replace_file(
    fs: &mut dyn Fs,
    path: &Path,
    tmp: &Path,
    bytes: &[u8],
) -> Result<(), FsError> {
    let own = create_temp(fs, tmp)?;
    let done = fs
        .write_all(&own, bytes)
        .and_then(|()| fs.sync_file(&own))
        .and_then(|()| fs.rename(&own, path));
    if done.is_err() {
        // The first error is the result. A failed remove leaves a file that no name uses.
        let _ = fs.remove(&own);
    }
    done
}

/// Reads a decimal number of a temporary file name: 1 to [`MAX_DIGITS`] ASCII digits with no
/// leading zero. Gives `None` for another text or for a value above `u64::MAX`.
fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > MAX_DIGITS || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    let mut value: u64 = 0;
    for byte in text.bytes() {
        let digit = byte.checked_sub(b'0').filter(|d| *d <= 9)?;
        value = value.checked_mul(10)?.checked_add(u64::from(digit))?;
    }
    Some(value)
}

/// Gives the process ID of `name` when it is a temporary file name of `base`:
/// `<base>.<pid>.<n>`. Gives `None` for a name of another shape.
pub(crate) fn temp_pid(name: &str, base: &str) -> Option<u32> {
    let rest = name.strip_prefix(base)?.strip_prefix('.')?;
    let (pid, n) = rest.split_once('.')?;
    decimal(n)?;
    u32::try_from(decimal(pid)?).ok()
}

/// Removes the temporary files of dead processes from the directory `dir`.
///
/// An entry goes when these are true:
///
/// - It is a file, and its name is `<base>.<pid>.<n>` with a `base` of `bases`.
/// - It changed at least [`TEMP_GRACE`] before `now`, and `dead` gives `true` for `pid`.
///
/// The temporary files of this process stay. The step reads at most [`SWEEP_MAX`] entries.
/// A failed list or remove leaves the files. Gives the number of removed files.
pub(crate) fn remove_dead_temps(
    fs: &mut dyn Fs,
    dir: &Path,
    bases: &[&str],
    dead: fn(&mut dyn Fs, u32) -> bool,
    now: SystemTime,
) -> usize {
    let pid_of = |name: &str| bases.iter().find_map(|base| temp_pid(name, base));
    remove_dead_temps_by(fs, dir, &pid_of, dead, now)
}

/// Removes the temporary files of dead processes from the directory `dir`, with the names
/// that `pid_of` accepts.
///
/// `pid_of` gives the process ID of a temporary file name, or `None` for another name. The
/// other rules are the rules of [`remove_dead_temps`]. Gives the number of removed files.
pub(crate) fn remove_dead_temps_by(
    fs: &mut dyn Fs,
    dir: &Path,
    pid_of: &dyn Fn(&str) -> Option<u32>,
    dead: fn(&mut dyn Fs, u32) -> bool,
    now: SystemTime,
) -> usize {
    let Ok(names) = fs.list(dir) else {
        return 0;
    };
    let me = std::process::id();
    let mut removed: usize = 0;
    for name in names.iter().take(SWEEP_MAX) {
        let Some(pid) = pid_of(name) else {
            continue;
        };
        let path = dir.join(name);
        let old = fs
            .modified(&path)
            .and_then(|changed| now.duration_since(changed).ok())
            .is_some_and(|age| age >= TEMP_GRACE);
        if pid == me || fs.kind(&path) != Some(EntryKind::File) || !old || !dead(fs, pid) {
            continue;
        }
        if fs.remove(&path).is_ok() {
            removed = removed.saturating_add(1);
        }
    }
    removed
}
