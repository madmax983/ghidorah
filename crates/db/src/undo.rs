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
//! - An analysis run marker has no edits. No undo selects it.
//! - A commit changes one fact layer. A `count` stops at an entry of the other layer. An entry
//!   of the analysis layer reverts in a commit with the source `analysis`.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::{ErrorCode, Rev, TxId};

use crate::edit::{EditError, Layer};
use crate::fact::SessionLabel;
use crate::history::{Entry, EntryState, History, Scope};
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
    let (selected, layer) = select(history, req)?;
    let source = match layer {
        Layer::Analysis => Source::Analysis,
        Layer::Base => req.source,
    };
    let mut tx = program
        .begin(UNDO_LABEL, source, req.session.clone())
        .map_err(UndoError::Tx)?;
    let mut of = Vec::new();
    for id in &selected {
        let edits = history
            .entry(*id)
            .and_then(|e| e.edits.as_ref())
            .ok_or(UndoError::NotInvertible(*id))?;
        for a in edits.iter().rev() {
            if tx
                .restore(a.inverse.clone())
                .map_err(UndoError::Edit)?
                .is_some()
            {
                of.push(*id);
            }
        }
    }
    let planned = tx.edits().to_vec();
    let start_band = planned.iter().filter_map(|a| a.edit.kind().band()).min();
    if req.dry_run {
        tx.abort();
        return Ok(UndoOutcome {
            line: None,
            entries: selected,
            planned,
            rev: program.rev(),
            start_band,
        });
    }
    let commit = tx.commit().map_err(UndoError::Tx)?;
    if commit.noop {
        return Err(nothing(req.redo));
    }
    let user = selected
        .iter()
        .filter_map(|id| history.entry(*id))
        .any(|e| e.source == Source::User);
    let line = TxLine {
        rev: commit.rev,
        tx: commit.tx,
        label: commit.label,
        source: commit.source,
        session: commit.session,
        force: req.force && user,
        edits: commit.edits,
        of,
        undo_of: if req.redo {
            Vec::new()
        } else {
            selected.clone()
        },
        redo_of: if req.redo {
            selected.clone()
        } else {
            Vec::new()
        },
    };
    Ok(UndoOutcome {
        planned: line.edits.clone(),
        rev: line.rev,
        line: Some(line),
        entries: selected,
        start_band,
    })
}

/// Gives the error of a scope with no entry in reach.
const fn nothing(redo: bool) -> UndoError {
    if redo {
        UndoError::NothingToRedo
    } else {
        UndoError::NothingToUndo
    }
}

/// The entry states of a request: the history states with the entries of the request so far.
struct States<'h> {
    history: &'h History,
    changed: BTreeMap<TxId, EntryState>,
}

impl States<'_> {
    fn of(&self, e: &Entry) -> EntryState {
        self.changed.get(&e.tx).copied().unwrap_or(e.state)
    }

    /// Checks the force rule and the overlap of later applied entries.
    fn check(&self, e: &Entry, req: &UndoRequest) -> Result<(), UndoError> {
        if e.source == Source::User && req.source == Source::Agent && !req.force {
            return Err(UndoError::UserTx(e.tx));
        }
        let later: Vec<TxId> = self
            .history
            .entries()
            .filter(|l| l.tx > e.tx && self.of(l) == EntryState::Applied)
            .filter(|l| !l.keys.is_disjoint(&e.keys))
            .map(|l| l.tx)
            .collect();
        if later.is_empty() {
            Ok(())
        } else {
            Err(UndoError::Conflict { tx: e.tx, later })
        }
    }

    /// Gives the next entry of a request with no `tx`.
    fn next(&self, req: &UndoRequest) -> Option<&Entry> {
        let found = self
            .history
            .entries()
            .filter(|e| req.scope.holds(&e.session) && e.edits.is_some());
        if req.redo {
            let e = found
                .filter(|e| self.of(e) == EntryState::Undone)
                .max_by_key(|e| e.changed_by)?;
            let reach = self.history.last_original(&req.scope);
            (reach < Some(e.changed_by)).then_some(e)
        } else {
            found.rev().find(|e| self.of(e) == EntryState::Applied)
        }
    }
}

/// Selects the entries of a request in apply order. Gives them with their fact layer.
fn select(history: &History, req: &UndoRequest) -> Result<(Vec<TxId>, Layer), UndoError> {
    let mut states = States {
        history,
        changed: BTreeMap::new(),
    };
    let want = if req.redo {
        EntryState::Undone
    } else {
        EntryState::Applied
    };
    if let Some(tx) = req.tx {
        let e = history.entry(tx).ok_or(UndoError::UnknownTx(tx))?;
        if e.state != want {
            return Err(nothing(req.redo));
        }
        if e.edits.is_none() {
            return Err(UndoError::NotInvertible(tx));
        }
        states.check(e, req)?;
        return Ok((vec![tx], Layer::of(e.source).unwrap_or(Layer::Base)));
    }
    let mut out = Vec::new();
    let mut layer = None;
    for _ in 0..req.count.clamp(1, MAX_COUNT) {
        let Some(e) = states.next(req) else {
            break;
        };
        let this = Layer::of(e.source).unwrap_or(Layer::Base);
        if layer.is_some_and(|l| l != this) {
            break;
        }
        states.check(e, req)?;
        layer = Some(this);
        out.push(e.tx);
        let state = if req.redo {
            EntryState::Applied
        } else {
            EntryState::Undone
        };
        states.changed.insert(e.tx, state);
    }
    match layer {
        Some(l) if !out.is_empty() => Ok((out, l)),
        _ => Err(nothing(req.redo)),
    }
}
