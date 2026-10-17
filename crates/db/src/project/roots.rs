//! The projects root: the git-tree rule of ADR-0022 and the list of projects.

use std::path::Path;

use ghidorah_base::{BinaryId, Rev};

use super::{ProjectError, disk};
use crate::fs::Fs;

/// Tells if `path` or one of its parents holds a `.git` entry: a git working tree.
pub fn inside_git_tree(fs: &mut dyn Fs, path: &Path) -> bool {
    path.ancestors().any(|dir| fs.exists(&dir.join(".git")))
}

/// Checks a projects root (ADR-0022). A default root must be outside every git working tree.
/// A root that `--project-root` names can be anywhere.
///
/// # Errors
///
/// Returns [`ProjectError::InsideGitTree`] for a default root inside a git working tree.
pub fn check_root(fs: &mut dyn Fs, root: &Path, named: bool) -> Result<(), ProjectError> {
    if !named && inside_git_tree(fs, root) {
        return Err(ProjectError::InsideGitTree(root.to_path_buf()));
    }
    Ok(())
}

/// One project on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSummary {
    /// The binary ID.
    pub binary_id: BinaryId,
    /// The file name of the input.
    pub file_name: String,
    /// The revision of the last commit line.
    pub rev: Rev,
    /// The session of the last commit line, or `None`.
    pub last_session: Option<String>,
}

/// Gives the projects under `root`, newest revision first, then binary ID order.
///
/// A directory that is not a project, or a project with a bad project file, does not count.
pub fn list(fs: &mut dyn Fs, root: &Path) -> Vec<ProjectSummary> {
    disk::list(fs, root)
}
