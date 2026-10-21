//! The `fix_commits` step of `xtask ci` (AC-234).
//!
//! Each commit whose subject starts with `fix:` must change at least one Rust test file. A
//! golden or a data file under `tests` is not a test file. The step reads
//! `git log --name-only` with the format [`LOG_FORMAT`].

use std::path::Path;
use std::process::Command;

/// The subject prefix of a bug fix commit.
pub const FIX_PREFIX: &str = "fix:";

/// The `git log` format of the step: a marker line with the short hash and the subject.
pub const LOG_FORMAT: &str = "@@%h %s";

/// The marker at the start of the header line of one commit.
const MARKER: &str = "@@";

/// Tells if `path` is a test file: a `tests.rs` file, or a `.rs` file under a `tests`
/// directory.
///
/// A golden file or a data file under `tests` is not a test file. A fix needs a test that
/// fails before the fix (CLAUDE.md, TDD process).
#[must_use]
pub fn is_test_file(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    let Some((file, dirs)) = parts.split_last() else {
        return false;
    };
    *file == "tests.rs"
        || (dirs.contains(&"tests") && Path::new(file).extension().is_some_and(|ext| ext == "rs"))
}

/// One commit of the log: its header `<hash> <subject>` and its changed files.
struct Commit<'a> {
    header: &'a str,
    files: Vec<&'a str>,
}

impl Commit<'_> {
    /// Tells if the subject starts with [`FIX_PREFIX`].
    fn is_fix(&self) -> bool {
        self.header
            .split_once(' ')
            .is_some_and(|(_, subject)| subject.starts_with(FIX_PREFIX))
    }
}

/// Splits the log into commits.
fn commits(log: &str) -> Vec<Commit<'_>> {
    let mut out: Vec<Commit<'_>> = Vec::new();
    for line in log.lines() {
        if let Some(header) = line.strip_prefix(MARKER) {
            out.push(Commit {
                header,
                files: Vec::new(),
            });
        } else if let Some(commit) = out.last_mut()
            && !line.trim().is_empty()
        {
            commit.files.push(line.trim());
        }
    }
    out
}

/// Gives `<hash> <subject>` of each `fix:` commit of `log` that changes no test file.
///
/// `log` is the output of `git log --name-only --format=<LOG_FORMAT>`.
#[must_use]
pub fn fix_commits_without_tests(log: &str) -> Vec<String> {
    commits(log)
        .iter()
        .filter(|c| c.is_fix() && !c.files.iter().any(|f| is_test_file(f)))
        .map(|c| c.header.to_owned())
        .collect()
}

/// Gives the number of `fix:` commits of `log`.
#[must_use]
pub fn fix_commit_count(log: &str) -> usize {
    commits(log).iter().filter(|c| c.is_fix()).count()
}

/// Gives the `git log` command of the step.
#[must_use]
pub fn log_command(root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.args(["log", "--name-only", &format!("--format={LOG_FORMAT}")])
        .current_dir(root);
    cmd
}
