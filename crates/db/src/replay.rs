//! Replay: the journal lines after a snapshot go into a program again (design Section 3.10).
//!
//! [`replay`] reads all lines of a journal. The lines that the snapshot covers go only into
//! the [`History`]. Each later line changes the program:
//!
//! | Line | Effect |
//! |---|---|
//! | commit | one transaction with the types and the exact edits of the line, at the same `rev` and `tx` |
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
    let mut out = Replay::default();
    for (i, line) in lines.iter().enumerate() {
        let covered = i < skip;
        let fail = |reason: String| ReplayError {
            line: i.saturating_add(1),
            reason,
        };
        match line {
            Line::Tx(t) => {
                if !covered {
                    apply_tx(program, t).map_err(fail)?;
                }
                history.record(t);
            }
            Line::Run(r) => {
                if !covered {
                    next_ids(program, r.rev, r.tx).map_err(fail)?;
                    skip_to(program, r.rev, r.tx);
                    out.behind = true;
                }
                out.last_run = Some(*r);
                history.record_run(r);
            }
            Line::Meta(m) => {
                if !covered {
                    meta::apply(program, m);
                }
                history.record_meta(m);
            }
        }
        if !covered {
            out.applied = out.applied.saturating_add(1);
        }
    }
    Ok(out)
}

/// Checks that `rev` and `tx` are the next revision and the next transaction of `program`.
fn next_ids(program: &Program, rev: Rev, tx: TxId) -> Result<(), String> {
    let want_rev = program.rev().0.checked_add(1);
    let want_tx = program.last_tx().0.checked_add(1);
    if want_rev == Some(rev.0) && want_tx == Some(tx.0) {
        Ok(())
    } else {
        Err(format!(
            "the line has rev {} and {tx}, and the program needs the next rev after {}",
            rev.0,
            program.rev().0
        ))
    }
}

/// Applies one commit line to `program` with its exact edits.
///
/// # Errors
///
/// Returns the reason when the line has a wrong `rev` or `tx`, or an edit does not apply to
/// the exact inverse of the line.
pub fn apply_tx(program: &mut Program, line: &TxLine) -> Result<(), String> {
    next_ids(program, line.rev, line.tx)?;
    let mut tx = program
        .begin(line.label.as_str(), line.source, line.session.clone())
        .map_err(|e| e.to_string())?;
    tx.replay_types(&line.types).map_err(|e| e.to_string())?;
    for a in &line.edits {
        let same = tx
            .restore(a.edit.clone())
            .map_err(|e| e.to_string())?
            .is_some_and(|applied| applied.inverse == a.inverse);
        if !same {
            return Err(format!(
                "the edit {} does not give the inverse of the line",
                a.edit.kind()
            ));
        }
    }
    let commit = tx.commit().map_err(|e| e.to_string())?;
    if commit.noop {
        return Err("the line has no edit".to_owned());
    }
    if commit.types != line.types {
        return Err("the types of the line do not give the same inputs".to_owned());
    }
    Ok(())
}

/// Moves the revision and the transaction counter of `program` to `rev` and `tx`, for an
/// analysis run line.
pub(crate) fn skip_to(program: &mut Program, rev: Rev, tx: TxId) {
    program.set_rev(rev);
    program.changes_mut().last_tx = tx;
}
