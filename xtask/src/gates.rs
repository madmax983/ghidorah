//! The static workspace gates and the `xtask gates` command.
//!
//! Each gate maps one AC to a check over the repository.
//! The tests in `xtask/tests/gates.rs` run the same gates.

use std::path::{Path, PathBuf};

use crate::json::Value;
use crate::workspace::Metadata;
use crate::{Error, Finding};

/// The repository that the gates check.
#[derive(Debug, Clone)]
pub struct Repo {
    /// The workspace root.
    pub root: PathBuf,
    /// The workspace model.
    pub meta: Metadata,
}

impl Repo {
    /// Loads the workspace model of `root`.
    ///
    /// # Errors
    ///
    /// Returns an error when `cargo metadata` fails.
    pub fn load(root: &Path) -> Result<Self, Error> {
        let _ = root;
        Err(Error::data("repo", "loader missing"))
    }

    /// Reads a file relative to the root.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the read fails.
    pub fn read(&self, rel: &str) -> Result<String, Error> {
        let path = self.root.join(rel);
        std::fs::read_to_string(&path).map_err(|e| Error::io(path, e))
    }
}

/// One gate.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    /// The AC that the gate checks, for example `AC-012`.
    pub ac: &'static str,
    /// A short statement of the rule.
    pub summary: &'static str,
    /// The check.
    pub check: fn(&Repo) -> Result<Vec<Finding>, Error>,
}

/// Every static gate, in AC order.
pub const GATES: &[Gate] = &[];

/// Gives the gate of an AC.
#[must_use]
pub fn find(ac: &str) -> Option<&'static Gate> {
    GATES.iter().find(|g| g.ac == ac)
}

/// Runs the gate of one AC.
///
/// # Errors
///
/// Returns [`Error::Usage`] for an unknown AC, or the error of the check.
pub fn check(repo: &Repo, ac: &str) -> Result<Vec<Finding>, Error> {
    find(ac).map_or_else(
        || Err(Error::Usage(format!("no gate for {ac}"))),
        |g| (g.check)(repo),
    )
}

/// Runs `xtask gates [AC...]`. Without arguments, it runs every gate.
///
/// # Errors
///
/// Returns an error when the repository does not load or a check fails to run.
pub fn run(root: &Path, args: &[String]) -> Result<Value, Error> {
    let _ = (root, args);
    Err(Error::Usage("gates".to_owned()))
}
