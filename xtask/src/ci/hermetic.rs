//! The `test_hermetic` step of `xtask ci` (AC-020).
//!
//! The step builds the tier-1 test binaries. Then it runs each binary in its package
//! directory with `PATH` reduced to the toolchain directory and an empty `HOME`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::json::{self, Value};
use crate::{Error, proc};

/// The variables that the hermetic run removes, so no test reads a user directory or the
/// `rustup` proxy of the parent process.
pub const REMOVED_VARS: &[&str] = &[
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "CARGO_HOME",
    "CARGO",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
];

/// Gives the environment changes of the hermetic run: `Some` sets a variable, `None` removes
/// it.
#[must_use]
pub fn hermetic_env(toolchain_bin: &Path, home: &Path) -> Vec<(String, Option<OsString>)> {
    let mut out = vec![
        (
            "PATH".to_owned(),
            Some(toolchain_bin.as_os_str().to_owned()),
        ),
        ("HOME".to_owned(), Some(home.as_os_str().to_owned())),
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
    /// The failed binaries, each with the last lines of its output.
    pub failed: Vec<(String, String)>,
    /// The toolchain directory of `PATH`.
    pub toolchain: PathBuf,
}

/// Builds the test binaries and runs each one with the hermetic environment.
///
/// # Errors
///
/// Returns an error when the build fails or a process does not start.
pub fn run_hermetic(root: &Path) -> Result<Hermetic, Error> {
    let built = proc::run_ok(&mut build_command(root))?;
    let binaries = test_binaries(&built.stdout);
    let toolchain = toolchain_bin(root)?;
    let home = root.join("target").join("xtask-ci").join("hermetic-home");
    if home.exists() {
        std::fs::remove_dir_all(&home).map_err(|e| Error::io(&home, e))?;
    }
    std::fs::create_dir_all(&home).map_err(|e| Error::io(&home, e))?;
    let mut failed = Vec::new();
    for binary in &binaries {
        let mut cmd = Command::new(&binary.exe);
        cmd.current_dir(&binary.dir)
            .env("CARGO_MANIFEST_DIR", &binary.dir)
            .env("GHIDORAH_REQUIRE_PROOFS", "1");
        for (key, value) in hermetic_env(&toolchain, &home) {
            match value {
                Some(v) => cmd.env(key, v),
                None => cmd.env_remove(key),
            };
        }
        let out = proc::run(&mut cmd)?;
        if !out.ok() {
            let name = binary
                .exe
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            let tail = format!(
                "{}\n{}",
                proc::tail(&out.stdout, 20),
                proc::tail(&out.stderr, 20)
            );
            failed.push((name, tail));
        }
    }
    Ok(Hermetic {
        binaries: binaries.len(),
        failed,
        toolchain,
    })
}
