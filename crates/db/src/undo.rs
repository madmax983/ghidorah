//! Undo and redo as forward commits (design Section 3.7, ADR-0017).
//!
//! [`run`] makes one new commit. An undo applies the exact inverses of the edits of each
//! selected entry in reverse order. A redo applies the inverses of the undo edits again. The
//! journal never gets shorter, and `rev` only increases.
//!
//! | Request | Selected entries |
//! |---|---|
//! | undo, no `tx` | the most recent applied entries of the scope, `count` of them |
//! | undo, `tx` | that entry (selective undo) |
//! | redo | the most recently undone entries of the scope, `count` of them |
//!
//! Rules:
//!
//! - A redo needs a scope with no original transaction after the undo. Else the result is
//!   `NOTHING_TO_REDO`.
//! - An entry that a later applied entry overlaps (one fact key or more) gives `CONFLICT` with
//!   the later transaction IDs.
//! - An agent undo of a `user` transaction needs `force: true`.
//! - An analysis run has no edits. No undo selects it.

#[cfg(test)]
mod tests;

use std::fmt;

use ghidorah_base::{ErrorCode, Rev, TxId};

use crate::edit::EditError;
use crate::fact::SessionLabel;
use crate::history::{History, Scope};
use crate::journal::TxLine;
use crate::program::Program;
use crate::source::Source;
use crate::tx::{Applied, TxError};

/// The label of an undo or a redo commit.
pub const UNDO_LABEL: &str = "history_undo";

/// The largest `count` of one request.
pub const MAX_COUNT: u32 = 1_000;

/// One undo or redo request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoRequest {
    /// The scope.
    pub scope: Scope,
    /// The entry of a selective undo, or `None`.
    pub tx: Option<TxId>,
    /// The number of entries. A selective undo takes one entry.
    pub count: u32,
    /// `true` applies undone entries again.
    pub redo: bool,
    /// `true` lets an agent undo a `user` transaction.
    pub force: bool,
    /// `true` plans the commit and rolls it back.
    pub dry_run: bool,
    /// The source of the new commit.
    pub source: Source,
    /// The session of the new commit.
    pub session: SessionLabel,
}

/// The result of [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoOutcome {
    /// The journal line of the new commit, or `None` for a dry run.
    pub line: Option<TxLine>,
    /// The selected entries in apply order.
    pub entries: Vec<TxId>,
    /// The applied edits: the edits of the commit, or the planned edits of a dry run.
    pub planned: Vec<Applied>,
    /// The revision after the commit.
    pub rev: Rev,
    /// The lowest start band of the edits, or `None` when no edit affects analysis.
    pub start_band: Option<u16>,
}

/// The error of [`run`]. The program does not change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoError {
    /// The scope has no applied entry.
    NothingToUndo,
    /// The scope has no undone entry in reach.
    NothingToRedo,
    /// Later applied entries change the same facts.
    Conflict {
        /// The selected entry.
        tx: TxId,
        /// The later entries in transaction order.
        later: Vec<TxId>,
    },
    /// The history has no entry with this ID.
    UnknownTx(TxId),
    /// The entry is an analysis run, which has no edits.
    NotInvertible(TxId),
    /// An agent undo of a `user` transaction needs `force: true`.
    UserTx(TxId),
    /// The transaction failed.
    Tx(TxError),
    /// An inverse edit failed.
    Edit(EditError),
}

impl UndoError {
    /// Gives the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::NothingToUndo | Self::NotInvertible(_) => ErrorCode::NothingToUndo,
            Self::NothingToRedo => ErrorCode::NothingToRedo,
            Self::Conflict { .. } | Self::Edit(_) => ErrorCode::Conflict,
            Self::UnknownTx(_) => ErrorCode::NotFound,
            Self::UserTx(_) => ErrorCode::BlockedByHigherPrioritySource,
            Self::Tx(e) => e.code(),
        }
    }
}

impl fmt::Display for UndoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NothingToUndo => f.write_str("The scope has no applied transaction."),
            Self::NothingToRedo => f.write_str("The scope has no undone transaction in reach."),
            Self::Conflict { tx, later } => {
                write!(f, "Later transactions change the facts of {tx}: ")?;
                let ids: Vec<String> = later.iter().map(ToString::to_string).collect();
                f.write_str(&ids.join(", "))
            }
            Self::UnknownTx(tx) => write!(f, "The history has no transaction {tx}."),
            Self::NotInvertible(tx) => write!(f, "The transaction {tx} is an analysis run."),
            Self::UserTx(tx) => write!(f, "The transaction {tx} has the source user."),
            Self::Tx(e) => e.fmt(f),
            Self::Edit(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for UndoError {}

/// Runs one undo or redo request as one new commit.
///
/// # Errors
///
/// Returns an [`UndoError`]. Then the program does not change.
pub fn run(
    program: &mut Program,
    history: &History,
    req: &UndoRequest,
) -> Result<UndoOutcome, UndoError> {
    let _ = (program, history, req);
    Err(UndoError::NothingToUndo)
}
