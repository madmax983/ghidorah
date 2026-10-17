//! The Tx guard: the only public write path of a program (design Section 3.7, ADR-0003).
//!
//! ```text
//! let mut tx = program.begin("symbol_rename", Source::Agent, session)?;
//! let name = tx.fact("parse_cfg".to_string());
//! tx.apply(Edit::SetName { addr, key: None, kind, primary: true, name: Some(name), evidence })?;
//! let commit = tx.commit()?;
//! ```
//!
//! Rules:
//!
//! - Each forward edit holds facts with the origin of the Tx: [`Tx::fact`] makes them.
//! - A failed edit changes nothing. The Tx stays open.
//! - An abort of a [`Nested`] scope rolls back its edits and poisons the whole Tx. A poisoned
//!   Tx refuses each edit, and its commit rolls back.
//! - A Tx dropped without a commit rolls back. During a panic, the drop does not roll back.
//!   Then the session drops the program and reloads it (AC-148).
//! - A commit with edits increments `rev` by exactly 1 and appends its events. A commit with
//!   no effective change is a no-op: it gives `noop: true` and keeps `rev` (AC-127).
//! - Each commit with edits takes the next transaction ID. A rollback or a no-op takes none.
//! - Under `debug_assertions`, each commit runs [`Program::check_invariants`].

#[cfg(test)]
mod tests;

use std::fmt;

use ghidorah_base::{ErrorCode, Rev, TxId};

use crate::edit::{Edit, EditError};
use crate::epochs::Epochs;
use crate::events::Events;
use crate::fact::{Fact, Origin, SessionLabel};
use crate::program::Program;
use crate::source::Source;

/// The longest transaction label in bytes.
pub const MAX_TX_LABEL: usize = 128;

/// A transaction label: 1 to [`MAX_TX_LABEL`] bytes of `[A-Za-z0-9._+-]`.
///
/// The default label of a tool call is the tool name. A batch joins the names with `+`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxLabel(String);

impl TxLabel {
    /// Makes a label.
    ///
    /// # Errors
    ///
    /// Returns [`TxError::BadLabel`] for an empty label, a label above [`MAX_TX_LABEL`] bytes
    /// or a byte outside `[A-Za-z0-9._+-]`.
    pub fn new(text: &str) -> Result<Self, TxError> {
        let _ = text;
        Err(TxError::BadLabel)
    }

    /// Gives the label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TxLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The error of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TxError {
    /// The source is `Default`. The DB never stores a default.
    DefaultSource,
    /// The label does not obey its grammar.
    BadLabel,
    /// A nested abort poisoned the Tx. The commit rolled back.
    Poisoned,
    /// The revision or the transaction counter is at `u64::MAX`.
    Exhausted,
}

impl TxError {
    /// Gives the error code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::DefaultSource | Self::BadLabel => ErrorCode::InvalidArgument,
            Self::Poisoned => ErrorCode::Conflict,
            Self::Exhausted => ErrorCode::LimitExceeded,
        }
    }
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DefaultSource => "A transaction cannot have the source default.",
            Self::BadLabel => "A transaction label has 1 to 128 bytes of [A-Za-z0-9._+-].",
            Self::Poisoned => "A nested abort poisoned the transaction. The commit rolled back.",
            Self::Exhausted => "The revision counter or the transaction counter is full.",
        })
    }
}

impl std::error::Error for TxError {}

/// One applied edit and its exact inverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The edit in its normal form.
    pub edit: Edit,
    /// The exact inverse: it puts back the state before the edit.
    pub inverse: Edit,
}

/// The result of a commit. The journal writes one line for a commit with edits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// The revision after the commit.
    pub rev: Rev,
    /// The transaction ID. A no-op does not use it.
    pub tx: TxId,
    /// The commit has no effective change.
    pub noop: bool,
    /// The label.
    pub label: TxLabel,
    /// The source.
    pub source: Source,
    /// The session label.
    pub session: SessionLabel,
    /// An edit of the Tx used `force: true`.
    pub force: bool,
    /// The applied edits in apply order.
    pub edits: Vec<Applied>,
}

impl Commit {
    /// Gives the lowest start band of the edits, or `None` when no edit affects analysis.
    #[must_use]
    pub fn start_band(&self) -> Option<u16> {
        None
    }
}

/// The transaction counter, the event ring and the table epochs of a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Changes {
    /// The ID of the last commit with edits.
    pub last_tx: TxId,
    /// The event ring.
    pub events: Events,
    /// The table epochs.
    pub epochs: Epochs,
}

impl Default for Changes {
    fn default() -> Self {
        Self {
            last_tx: TxId(0),
            events: Events::default(),
            epochs: Epochs::default(),
        }
    }
}

impl Program {
    /// Opens a transaction: the only public write path.
    ///
    /// # Errors
    ///
    /// Returns [`TxError::DefaultSource`] for the source `Default`, [`TxError::BadLabel`]
    /// for a bad label and [`TxError::Exhausted`] when the transaction counter is full.
    pub fn begin(
        &mut self,
        label: &str,
        source: Source,
        session: SessionLabel,
    ) -> Result<Tx<'_>, TxError> {
        let label = TxLabel(label.to_string());
        let origin = Origin::new(source, TxId(0), session, false);
        Ok(Tx {
            program: self,
            label,
            origin,
            log: Vec::new(),
            used_force: false,
            poisoned: false,
            open: true,
        })
    }

    /// Gives the ID of the last commit with edits, or 0.
    #[must_use]
    pub fn last_tx(&self) -> TxId {
        self.changes().last_tx
    }
}

/// An open transaction. See the module doc for its rules.
#[derive(Debug)]
pub struct Tx<'p> {
    program: &'p mut Program,
    label: TxLabel,
    origin: Origin,
    log: Vec<Applied>,
    used_force: bool,
    poisoned: bool,
    open: bool,
}

impl<'p> Tx<'p> {
    /// Gives the transaction ID. The commit uses it when the Tx has edits.
    #[must_use]
    pub const fn id(&self) -> TxId {
        self.origin.tx
    }

    /// Gives the origin of the facts of the Tx.
    #[must_use]
    pub const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Gives the label.
    #[must_use]
    pub const fn label(&self) -> &TxLabel {
        &self.label
    }

    /// Gives the revision that a commit with edits gives.
    #[must_use]
    pub fn pending_rev(&self) -> Rev {
        self.program.rev()
    }

    /// Sets the force flag of the next facts. `force` lets an `Agent` write replace an
    /// `Imported` fact. The journal records the flag.
    pub fn set_force(&mut self, force: bool) {
        let _ = force;
    }

    /// Makes a fact with the origin of the Tx.
    #[must_use]
    pub fn fact<T>(&self, value: T) -> Fact<T> {
        self.origin.fact(value)
    }

    /// Gives the program with the edits of the Tx.
    #[must_use]
    pub fn program(&self) -> &Program {
        self.program
    }

    /// Gives the applied edits in apply order.
    #[must_use]
    pub fn edits(&self) -> &[Applied] {
        &self.log
    }

    /// Tells if a nested abort poisoned the Tx.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Applies a forward edit. Gives the applied edit, or `None` for a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::Poisoned`] for a poisoned Tx, or the [`EditError`] of the edit.
    /// Then the program does not change.
    pub fn apply(&mut self, edit: Edit) -> Result<Option<&Applied>, EditError> {
        let _ = edit;
        Ok(None)
    }

    /// Applies an exact edit: an inverse, an undo or a replayed edit. It puts its exact state
    /// with no origin check and no write rule.
    ///
    /// # Errors
    ///
    /// Returns [`EditError::Poisoned`] for a poisoned Tx, or the [`EditError`] of the edit.
    pub(crate) fn restore(&mut self, edit: Edit) -> Result<Option<&Applied>, EditError> {
        let _ = edit;
        Ok(None)
    }

    /// Opens a nested scope. Its abort poisons this Tx.
    pub fn nest(&mut self) -> Nested<'_, 'p> {
        let mark = self.log.len();
        Nested {
            tx: self,
            mark,
            open: true,
        }
    }

    /// Commits the Tx.
    ///
    /// # Errors
    ///
    /// Returns [`TxError::Poisoned`] after a nested abort and [`TxError::Exhausted`] when the
    /// revision counter is full. Then the Tx rolls back.
    pub fn commit(mut self) -> Result<Commit, TxError> {
        self.open = false;
        Ok(Commit {
            rev: self.program.rev(),
            tx: self.origin.tx,
            noop: true,
            label: self.label.clone(),
            source: self.origin.source,
            session: self.origin.session.clone(),
            force: self.used_force,
            edits: std::mem::take(&mut self.log),
        })
    }

    /// Rolls the Tx back.
    pub fn abort(self) {}
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {}
}

/// A nested scope of a transaction. A drop without a commit rolls back its edits and
/// poisons the Tx.
#[derive(Debug)]
pub struct Nested<'t, 'p> {
    tx: &'t mut Tx<'p>,
    mark: usize,
    open: bool,
}

impl<'p> Nested<'_, 'p> {
    /// Applies a forward edit in the scope. See [`Tx::apply`].
    ///
    /// # Errors
    ///
    /// Returns the error of [`Tx::apply`].
    pub fn apply(&mut self, edit: Edit) -> Result<Option<&Applied>, EditError> {
        self.tx.apply(edit)
    }

    /// Gives the transaction of the scope.
    #[must_use]
    pub fn tx(&self) -> &Tx<'p> {
        self.tx
    }

    /// Opens a scope inside this scope.
    pub fn nest(&mut self) -> Nested<'_, 'p> {
        self.tx.nest()
    }

    /// Ends the scope and keeps its edits in the Tx.
    pub fn commit(mut self) {
        self.open = false;
    }

    /// Rolls back the edits of the scope and poisons the Tx.
    pub fn abort(self) {}
}

impl Drop for Nested<'_, '_> {
    fn drop(&mut self) {
        let _ = self.mark;
    }
}
