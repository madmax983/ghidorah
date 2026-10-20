//! One transaction for a batch with edits (design Sections 11.4 and 11.6).
//!
//! [`Session::batch_begin`] opens the batch of one binary. While it is open, each edit step
//! commits through [`Session::transact`] into one transaction:
//!
//! 1. The step starts from a copy of the program before the batch.
//! 2. The step applies the edits of the earlier steps again, then its own edits.
//! 3. The commit gives the program with all edits of the batch, at one rev and one
//!    transaction ID. The store writes no journal line yet.
//!
//! So every fact of the batch carries the transaction ID of the batch. A read step sees the
//! edits of the earlier steps. A re-analysis waits for the end of the batch, and reads see
//! the analysis state `stale`. [`Session::batch_commit`] writes the one journal line and
//! starts the re-analysis once. [`Session::batch_rollback`] puts back the program before the
//! batch. Meta lines (marks and progress rows) are not edits: they stay in both cases.

use ghidorah_base::{BinaryId, ErrorCode, Rev, TxId};
use ghidorah_db::{Applied, Commit, MetaLine, Program, Tx, TxLabel, TxLine, TypeInput, TypeMode};

use super::store::session_label;
use super::{RunReport, Session};
use crate::dispatch::Ctx;
use crate::envelope::{AnalysisInfo, AnalysisState};
use crate::errors::ToolError;

/// The edits of one step of a batch.
#[derive(Debug, Clone)]
struct StepEdits {
    /// The force flag of the facts of the step.
    force: bool,
    /// The C texts that the step parsed into the type store.
    types: Vec<TypeInput>,
    /// The applied edits of the step.
    edits: Vec<Applied>,
}

/// The open batch of one binary.
#[derive(Debug, Clone)]
pub struct BatchTx {
    /// The program before the batch, with the meta lines of the batch.
    base: Box<Program>,
    /// The label of the transaction.
    label: String,
    /// The analysis state before the batch.
    analysis: Option<AnalysisInfo>,
    /// The edits of each step with edits, in step order.
    steps: Vec<StepEdits>,
    /// The commit of all edits so far.
    merged: Option<Commit>,
    /// The lowest start band of the re-analysis, or `None`.
    band: Option<u16>,
}

impl BatchTx {
    /// Folds the meta line `line` into the program before the batch, so a roll back keeps
    /// it.
    pub(super) fn fold(&mut self, line: &MetaLine) {
        ghidorah_db::meta::apply(&mut self.base, line);
    }
}

/// The end of a batch with edits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCommit {
    /// The transaction ID, or `None` when no step changed a fact.
    pub tx: Option<TxId>,
    /// The rev after the commit and the re-analysis.
    pub rev: Rev,
    /// The report of the re-analysis, or `None` when no re-analysis ran.
    pub report: Option<RunReport>,
}

/// Gives the tool error of an edit that does not apply again in the same state.
fn replay_failed() -> ToolError {
    ToolError::new(ErrorCode::InternalError)
}

/// Applies the edits of the earlier steps of a batch to `tx`. Gives the number of type
/// inputs that they parse.
fn replay(tx: &mut Tx<'_>, steps: &[StepEdits]) -> Result<usize, ToolError> {
    let mut types = 0usize;
    for step in steps {
        tx.set_force(step.force);
        for input in &step.types {
            let parsed = match input.mode {
                TypeMode::Sig => tx.parse_sig(&input.text).map(drop),
                TypeMode::Type => tx.parse_type(&input.text).map(drop),
            };
            parsed.map_err(|_| replay_failed())?;
            types = types.saturating_add(1);
        }
        for applied in &step.edits {
            let again = tx
                .apply(applied.edit.clone())
                .map_err(|e| ToolError::new(e.code()))?;
            if again.map(|a| &a.inverse) != Some(&applied.inverse) {
                return Err(replay_failed());
            }
        }
    }
    tx.set_force(false);
    Ok(types)
}

impl Session {
    /// Opens the batch of the open binary `id`. The edits of the next steps form one
    /// transaction with the label `label`.
    ///
    /// # Errors
    ///
    /// Returns `UNKNOWN_BINARY` for a binary that is not open and `INVALID_ARGUMENT` for a
    /// label outside the grammar of transaction labels.
    pub fn batch_begin(&mut self, id: BinaryId, label: &str) -> Result<(), ToolError> {
        TxLabel::new(label).map_err(|e| ToolError::new(e.code()).var("field", "label"))?;
        let (Some(binary), Some(store)) = (self.binaries.get(&id), self.stores.get_mut(&id)) else {
            return Err(ToolError::new(ErrorCode::UnknownBinary));
        };
        store.batch = Some(Box::new(BatchTx {
            base: Box::new(binary.program.clone()),
            label: label.to_owned(),
            analysis: binary.analysis,
            steps: Vec::new(),
            merged: None,
            band: None,
        }));
        Ok(())
    }

    /// Gives the applied edits of the open batch of `id` in step order.
    #[must_use]
    pub fn batch_planned(&self, id: BinaryId) -> Vec<Applied> {
        self.stores
            .get(&id)
            .and_then(|s| s.batch.as_ref())
            .map(|b| b.steps.iter().flat_map(|s| s.edits.clone()).collect())
            .unwrap_or_default()
    }

    /// Ends the open batch of `id` with no commit: the program before the batch comes back.
    pub fn batch_rollback(&mut self, id: BinaryId) {
        let batch = self.stores.get_mut(&id).and_then(|s| s.batch.take());
        if let (Some(batch), Some(binary)) = (batch, self.binaries.get_mut(&id)) {
            binary.program = *batch.base;
            binary.analysis = batch.analysis;
        }
    }

    /// Ends the open batch of `id` with one commit: one journal line, then one re-analysis
    /// within the fuel of `ctx` when an edit affects the analysis. The re-analysis runs in the
    /// fuel slices of [`Session::analyze_sliced`], with the cancel checks of the call.
    ///
    /// # Errors
    ///
    /// Returns the error of a failed journal write, after which the program has the durable
    /// state, or the error of the engine.
    pub fn batch_commit(&mut self, id: BinaryId, ctx: &mut Ctx) -> Result<BatchCommit, ToolError> {
        let batch = self.stores.get_mut(&id).and_then(|s| s.batch.take());
        let (Some(batch), Some(binary)) = (batch, self.binaries.get_mut(&id)) else {
            return Err(ToolError::new(ErrorCode::UnknownBinary));
        };
        binary.analysis = batch.analysis;
        let Some(merged) = batch.merged else {
            return Ok(BatchCommit {
                tx: None,
                rev: binary.program.rev(),
                report: None,
            });
        };
        self.journal(id, &TxLine::of_commit(&merged))?;
        let report = match batch.band {
            Some(band) => self.reanalyze_sliced(id, band, ctx)?.map(|s| s.report()),
            None => None,
        };
        let rev = self
            .binaries
            .get(&id)
            .map_or(merged.rev, |b| b.program.rev());
        Ok(BatchCommit {
            tx: Some(merged.tx),
            rev,
            report,
        })
    }

    /// Tells if the binary `id` has an open batch.
    #[must_use]
    pub fn in_batch(&self, id: BinaryId) -> bool {
        self.stores.get(&id).is_some_and(|s| s.batch.is_some())
    }

    /// Notes the start band `band` of an edit in the open batch of `id`, and marks the
    /// analysis state `stale`. Gives `false` when `id` has no open batch.
    pub(super) fn batch_band(&mut self, id: BinaryId, band: u16) -> bool {
        let Some(batch) = self.stores.get_mut(&id).and_then(|s| s.batch.as_mut()) else {
            return false;
        };
        batch.band = Some(batch.band.map_or(band, |b| b.min(band)));
        if let Some(binary) = self.binaries.get_mut(&id) {
            binary.analysis = binary.analysis.map(|a| AnalysisInfo {
                state: AnalysisState::Stale,
                rev: a.rev,
            });
        }
        true
    }

    /// Runs `edit` as the next step of the open batch of `id`. See the module doc.
    ///
    /// # Errors
    ///
    /// Returns `READ_ONLY_PROJECT`, `INVALID_ARGUMENT` for a bad session label, or the error
    /// of `edit`. Then the program does not change.
    pub(super) fn transact_batch<T>(
        &mut self,
        id: BinaryId,
        session: &str,
        edit: impl FnOnce(&mut Tx<'_>) -> Result<T, ToolError>,
    ) -> Result<(Commit, T), ToolError> {
        let who = session_label(session)?;
        let source = self.config.source;
        let (Some(binary), Some(batch)) = (
            self.binaries.get_mut(&id),
            self.stores.get_mut(&id).and_then(|s| s.batch.as_mut()),
        ) else {
            return Err(ToolError::new(ErrorCode::UnknownBinary));
        };
        if binary.read_only {
            return Err(ToolError::new(ErrorCode::ReadOnlyProject));
        }
        let mut work = (*batch.base).clone();
        let mut tx = work
            .begin(&batch.label, source, who)
            .map_err(|e| ToolError::new(e.code()))?;
        let prior_types = replay(&mut tx, &batch.steps)?;
        let prior = tx.edits().len();
        let value = edit(&mut tx)?;
        let force = tx.origin().force;
        let commit = tx.commit().map_err(|e| ToolError::new(e.code()))?;
        let own: Vec<Applied> = commit.edits.get(prior..).unwrap_or_default().to_vec();
        if own.is_empty() {
            let noop = Commit {
                rev: binary.program.rev(),
                noop: true,
                edits: Vec::new(),
                types: Vec::new(),
                ..commit
            };
            return Ok((noop, value));
        }
        let types: Vec<TypeInput> = commit.types.get(prior_types..).unwrap_or_default().to_vec();
        batch.steps.push(StepEdits {
            force,
            types: types.clone(),
            edits: own.clone(),
        });
        binary.program = work;
        let step = Commit {
            edits: own,
            types,
            ..commit.clone()
        };
        batch.merged = Some(commit);
        Ok((step, value))
    }
}
