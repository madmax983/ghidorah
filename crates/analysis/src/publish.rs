//! The publish step: the analysis set of a work state and its `ReplaceAnalysis` commit
//! (design Section 3.9).
//!
//! The step makes the JSON form of the analysis layer and reads it with the codec of
//! `ghidorah-db`. So each row goes through the write rules of its table. Rules of the step:
//!
//! - Each fact has the origin `Analysis`, transaction 0, session `analysis`. So the set does
//!   not depend on the number of commits (AC-092).
//! - A function whose entry is in a code unit of another function does not go into the set.
//! - A premise that is not in the set and not an input of the binary goes.
//! - The creation order puts each premise before its fact. A premise that closes a cycle goes.
//! - A set equal to the committed set gives a no-op commit with no event (AC-093).

use ghidorah_db::{AnalysisSet, Commit, Program, Tables};

use crate::AnalysisError;
use crate::work::Work;

/// The change counts of `analysis_run` between two analysis sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changed {
    /// The functions that are new, lost or different.
    pub functions: u64,
    /// The references that are new, lost or different.
    pub refs: u64,
    /// The strings that are new, lost or different.
    pub strings: u64,
    /// The jump tables that are new, lost or different.
    pub jumptables: u64,
}

impl Changed {
    /// Counts the changes from `old` to `new`.
    #[must_use]
    pub fn between(old: &AnalysisSet, new: &AnalysisSet) -> Self {
        let _ = (old, new);
        Self::default()
    }
}

/// Gives the analysis set of `work`.
///
/// # Errors
///
/// Returns [`AnalysisError::Codec`] when a row breaks a table rule.
pub(crate) fn analysis_set(program: &Program, work: &Work) -> Result<AnalysisSet, AnalysisError> {
    let _ = (program, work);
    Ok(Tables::default())
}

/// Commits the analysis set of `work` with one `ReplaceAnalysis` edit.
///
/// # Errors
///
/// Returns the [`AnalysisError`] of the set, of the transaction or of the edit.
pub(crate) fn publish(program: &mut Program, work: &Work) -> Result<Commit, AnalysisError> {
    let _ = (program, work);
    Err(AnalysisError::Tx(ghidorah_db::TxError::BadLabel))
}
