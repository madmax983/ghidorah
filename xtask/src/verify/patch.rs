//! Negative patches: one unified-diff hunk against one kernel file (ADR-0011).
//!
//! `xtask verify` applies each patch to a copy of the kernel. The copy must fail verification.
//! The hunk must match the current source exactly once. So a stale patch fails with an error.

use std::fmt;

/// One parsed patch: one file and one hunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// The path of the changed file, relative to the workspace root.
    pub path: String,
    /// The lines of the hunk before the change: context lines and removed lines.
    pub old: Vec<String>,
    /// The lines of the hunk after the change: context lines and added lines.
    pub new: Vec<String>,
}

/// The cause of a patch failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// The patch has no `+++ b/<path>` line.
    NoFile,
    /// The patch has more than one file, or not exactly one hunk.
    NotOneHunk,
    /// A hunk line has a bad form, or the line counts differ from the hunk header.
    BadHunk(String),
    /// The old lines of the hunk do not occur in the source.
    Stale,
    /// The old lines of the hunk occur more than one time in the source.
    Ambiguous,
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFile => f.write_str("the patch names no file"),
            Self::NotOneHunk => {
                f.write_str("the patch does not have exactly one file and one hunk")
            }
            Self::BadHunk(line) => write!(f, "the hunk has a bad line: {line}"),
            Self::Stale => f.write_str("the hunk does not match the current source"),
            Self::Ambiguous => f.write_str("the hunk matches the source more than one time"),
        }
    }
}

impl std::error::Error for PatchError {}

/// Parses a unified diff with one file and one hunk.
///
/// # Errors
///
/// Gives a [`PatchError`] when the text is not one file with one valid hunk.
pub fn parse(text: &str) -> Result<Patch, PatchError> {
    let _ = text;
    Err(PatchError::NoFile)
}

/// Applies `patch` to `source` and gives the changed text.
///
/// # Errors
///
/// Gives [`PatchError::Stale`] or [`PatchError::Ambiguous`] when the old lines do not match one place.
pub fn apply(source: &str, patch: &Patch) -> Result<String, PatchError> {
    let _ = (source, patch);
    Err(PatchError::Stale)
}
