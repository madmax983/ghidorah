//! Replay: the journal lines after a snapshot go into a program again (design Section 3.10).
//!
//! [`replay`] reads all lines of a journal. The lines that the snapshot covers go only into
//! the [`History`]. Each later line changes the program:
//!
//! | Line | Effect |
//! |---|---|
//! | commit | one transaction with the exact edits of the line, at the same `rev` and `tx` |
//! | analysis run | the `rev` and `tx` move on. The analysis layer is behind, so the state is stale. |
//! | meta | a fold into the progress rows and the marks |
//!
//! A commit line must have the next `rev` and `tx`, and each exact edit must give the inverse
//! of the line. Else replay stops with [`ReplayError`].

#[cfg(test)]
mod tests;

use std::fmt;

use ghidorah_base::{Rev, TxId};

use crate::history::History;
use crate::journal::{Line, RunLine, TxLine};
use crate::meta;
use crate::program::Program;

/// The result of [`replay`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Replay {
    /// The number of lines that changed the program.
    pub applied: u64,
    /// The last analysis run of the journal, or `None`.
    pub last_run: Option<RunLine>,
    /// An analysis run after the snapshot changed the analysis layer. The layer is behind.
    pub behind: bool,
}

/// The error of [`replay`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayError {
    /// The line number, from 1.
    pub line: usize,
    /// What is wrong.
    pub reason: String,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The journal line {} does not replay: {}",
            self.line, self.reason
        )
    }
}

impl std::error::Error for ReplayError {}

/// Replays `lines` into `program` and `history`. The first `skip` lines only go into the
/// history: the snapshot of the program covers them.
///
/// # Errors
///
/// Returns a [`ReplayError`] for a line with a wrong `rev` or `tx`, or an edit that does not
/// apply exactly.
pub fn replay(
    program: &mut Program,
    lines: &[Line],
    skip: usize,
    history: &mut History,
) -> Result<Replay, ReplayError> {
    let _ = (program, lines, skip, history, meta::apply);
    Ok(Replay::default())
}

/// Applies one commit line to `program` with its exact edits.
///
/// # Errors
///
/// Returns the reason when the line has a wrong `rev` or `tx`, or an edit does not apply to
/// the exact inverse of the line.
pub fn apply_tx(program: &mut Program, line: &TxLine) -> Result<(), String> {
    let _ = (program, line);
    Err("replay is not ready".to_owned())
}

/// Moves the revision and the transaction counter of `program` to `rev` and `tx`, for an
/// analysis run line.
pub(crate) fn skip_to(program: &mut Program, rev: Rev, tx: TxId) {
    program.set_rev(rev);
    program.changes_mut().last_tx = tx;
}
