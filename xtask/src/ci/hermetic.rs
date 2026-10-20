//! The `test_hermetic` step of `xtask ci` (AC-020).
//!
//! The step builds the tier-1 test binaries. Then it runs each binary in its package
//! directory with `PATH` reduced to the toolchain directory and an empty `HOME`.
//!
//! `HOME` is a new directory under the system temp directory, outside every git work tree.
//! There, the default projects root of a spawned `ghidorah` is valid, so a write to it is
//! visible. The step fails when a binary writes a file under `HOME`. `CARGO_HOME` is a
//! different empty directory, because `cargo metadata` writes its cache there.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::json::{self, Value};
use crate::{Error, proc};

/// The `XDG_DATA_HOME` of the hermetic run, relative to its `HOME`.
pub const DATA_DIR: &str = ".local/share";

/// The largest number of paths that the step lists for one binary that writes under `HOME`.
const LISTED: usize = 20;

/// The variables that the hermetic run removes, so no test reads a user directory or the
/// `rustup` proxy of the parent process.
pub const REMOVED_VARS: &[&str] = &[
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "CARGO",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
];

/// Gives the environment changes of the hermetic run: `Some` sets a variable, `None` removes
/// it.
///
/// `XDG_DATA_HOME` is [`DATA_DIR`] under `home`, so the default projects root is under `home`.
#[must_use]
pub fn hermetic_env(
    toolchain_bin: &Path,
    home: &Path,
    cargo_home: &Path,
) -> Vec<(String, Option<OsString>)> {
    let mut out = vec![
        (
            "PATH".to_owned(),
            Some(toolchain_bin.as_os_str().to_owned()),
        ),
        ("HOME".to_owned(), Some(home.as_os_str().to_owned())),
        (
            "XDG_DATA_HOME".to_owned(),
            Some(home.join(DATA_DIR).into_os_string()),
        ),
        (
            "CARGO_HOME".to_owned(),
            Some(cargo_home.as_os_str().to_owned()),
        ),
    ];
    out.extend(REMOVED_VARS.iter().map(|v| ((*v).to_owned(), None)));
    out
}

/// One test binary of the hermetic run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TestBinary {
    /// The executable file.
    pub exe: PathBuf,
    /// The package directory: the working directory of the run.
    pub dir: PathBuf,
}

/// Gives the test binary of one JSON message of cargo, or `None`.
fn binary_of(message: &Value) -> Option<TestBinary> {
    let artifact = message.get("reason").and_then(Value::as_str) == Some("compiler-artifact");
    let test = message.pointer("/profile/test").and_then(Value::as_bool) == Some(true);
    if !(artifact && test) {
        return None;
    }
    let exe = message.get("executable").and_then(Value::as_str)?;
    let manifest = message.get("manifest_path").and_then(Value::as_str)?;
    Some(TestBinary {
        exe: PathBuf::from(exe),
        dir: Path::new(manifest).parent()?.to_path_buf(),
    })
}

/// Gives the test binaries of the JSON lines of `cargo test --no-run --message-format=json`.
///
/// The list holds each binary once, in path order. A line that is not JSON gives nothing.
#[must_use]
pub fn test_binaries(cargo_json: &str) -> Vec<TestBinary> {
    let mut out: Vec<TestBinary> = cargo_json
        .lines()
        .filter_map(|line| json::parse(line).ok())
        .filter_map(|message| binary_of(&message))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Gives the command that builds the tier-1 test binaries and lists them.
#[must_use]
pub fn build_command(root: &Path) -> Command {
    let mut cmd = proc::cargo_cmd(&["test", "--workspace", "--no-run", "--message-format=json"]);
    cmd.current_dir(root);
    cmd
}

/// Gives the `bin` directory of the active toolchain.
fn toolchain_bin(root: &Path) -> Result<PathBuf, Error> {
    let out = proc::run_ok(
        Command::new("rustc")
            .args(["--print", "sysroot"])
            .current_dir(root),
    )?;
    Ok(PathBuf::from(out.stdout.trim()).join("bin"))
}

/// The result of the hermetic run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hermetic {
    /// The number of test binaries.
    pub binaries: usize,
    /// The failed binaries, each with the paths that it writes under `HOME` and the last
    /// lines of its output.
    pub failed: Vec<(String, String)>,
    /// The toolchain directory of `PATH`.
    pub toolchain: PathBuf,
}

/// Builds the test binaries and runs each one with the hermetic environment.
///
/// # Errors
///
/// Returns an error when the build fails, the run directory is not available or a process
/// does not start.
pub fn run_hermetic(root: &Path) -> Result<Hermetic, Error> {
    let built = proc::run_ok(&mut build_command(root))?;
    let binaries = test_binaries(&built.stdout);
    let toolchain = toolchain_bin(root)?;
    run_binaries(&binaries, &toolchain)
}

/// Runs each binary with the hermetic environment, a new empty `HOME` and a new empty
/// `CARGO_HOME`.
///
/// After each binary, the run makes sure that `HOME` is still empty. A binary that fails, or
/// that writes under `HOME`, goes in the failed list. The run removes both directories at the
/// end.
///
/// # Errors
///
/// Returns an error when the run directory is inside a git work tree, or when the function
/// cannot make or read it. A process that does not start also gives an error.
pub fn run_binaries(binaries: &[TestBinary], toolchain: &Path) -> Result<Hermetic, Error> {
    let dir = new_run_dir()?;
    let failed = run_in_home(binaries, toolchain, &dir);
    let removed = std::fs::remove_dir_all(&dir).map_err(|e| Error::io(&dir, e));
    let failed = failed?;
    removed?;
    Ok(Hermetic {
        binaries: binaries.len(),
        failed,
        toolchain: toolchain.to_path_buf(),
    })
}

/// Runs each binary with `HOME` and `CARGO_HOME` in the run directory `dir`, and gives the
/// failed binaries.
fn run_in_home(
    binaries: &[TestBinary],
    toolchain: &Path,
    dir: &Path,
) -> Result<Vec<(String, String)>, Error> {
    let home = dir.join("home");
    let cargo_home = dir.join("cargo");
    reset(&home)?;
    reset(&cargo_home)?;
    let mut failed = Vec::new();
    for binary in binaries {
        let mut cmd = Command::new(&binary.exe);
        cmd.current_dir(&binary.dir)
            .env("CARGO_MANIFEST_DIR", &binary.dir)
            .env("GHIDORAH_REQUIRE_PROOFS", "1");
        for (key, value) in hermetic_env(toolchain, &home, &cargo_home) {
            match value {
                Some(v) => cmd.env(key, v),
                None => cmd.env_remove(key),
            };
        }
        let out = proc::run(&mut cmd)?;
        let mut problems = Vec::new();
        let wrote = written(&home)?;
        if !wrote.is_empty() {
            problems.push(format!(
                "the binary writes under HOME: {}",
                wrote.join(", ")
            ));
            reset(&home)?;
        }
        if !out.ok() {
            problems.push(format!(
                "{}\n{}",
                proc::tail(&out.stdout, 20),
                proc::tail(&out.stderr, 20)
            ));
        }
        if !problems.is_empty() {
            let name = binary
                .exe
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            failed.push((name, problems.join("\n")));
        }
    }
    Ok(failed)
}

/// Tells if `path` or one of its parent directories holds a `.git` entry.
fn in_git_tree(path: &Path) -> bool {
    path.ancestors().any(|dir| dir.join(".git").exists())
}

/// Makes a new empty run directory under the system temp directory.
///
/// # Errors
///
/// Returns an error when the directory is inside a git work tree. It also returns an error
/// when the function cannot make the directory.
fn new_run_dir() -> Result<PathBuf, Error> {
    static RUNS: AtomicU64 = AtomicU64::new(0);
    let run = RUNS.fetch_add(1, Ordering::Relaxed);
    let name = format!("ghidorah-hermetic-{}-{run}", std::process::id());
    let dir = std::env::temp_dir().join(name);
    if in_git_tree(&dir) {
        return Err(Error::data(
            "test_hermetic",
            format!("the run directory {} is in a git work tree", dir.display()),
        ));
    }
    reset(&dir)?;
    Ok(dir)
}

/// Removes `dir` and its content, then makes `dir` again as an empty directory.
///
/// # Errors
///
/// Returns an error when the function cannot remove or make the directory.
fn reset(dir: &Path) -> Result<(), Error> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(dir, e)),
    }
    std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))
}

/// Gives the paths under `home`, relative to it, in breadth-first name order.
///
/// The list holds at most [`LISTED`] paths. The walk does not follow a symbolic link.
///
/// # Errors
///
/// Returns an error when the function cannot read a directory.
fn written(home: &Path) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    let mut queue = VecDeque::from([home.to_path_buf()]);
    while let Some(dir) = queue.pop_front() {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e| Error::io(&dir, e))? {
            let entry = entry.map_err(|e| Error::io(&dir, e))?;
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            entries.push((entry.path(), is_dir));
        }
        entries.sort();
        for (path, is_dir) in entries {
            if out.len() >= LISTED {
                return Ok(out);
            }
            let rel = path.strip_prefix(home).unwrap_or(&path);
            out.push(rel.display().to_string());
            if is_dir {
                queue.push_back(path);
            }
        }
    }
    Ok(out)
}
