//! The `fix_commits` step of `xtask ci` (AC-234).
//!
//! Each commit whose subject starts with `fix:` must change at least one test file. The step
//! reads `git log --name-only` with the format [`LOG_FORMAT`].

/// The subject prefix of a bug fix commit.
pub const FIX_PREFIX: &str = "fix:";

/// The `git log` format of the step: a marker line with the short hash and the subject.
pub const LOG_FORMAT: &str = "@@%h %s";

/// Tells if `path` is a test file: a file under a `tests` directory, or a `tests.rs` file.
#[must_use]
pub fn is_test_file(path: &str) -> bool {
    let _ = path;
    false
}

/// Gives `<hash> <subject>` of each `fix:` commit of `log` that changes no test file.
///
/// `log` is the output of `git log --name-only --format=<LOG_FORMAT>`.
#[must_use]
pub fn fix_commits_without_tests(log: &str) -> Vec<String> {
    let _ = log;
    Vec::new()
}

/// Gives the number of `fix:` commits of `log`.
#[must_use]
pub fn fix_commit_count(log: &str) -> usize {
    let _ = log;
    0
}
