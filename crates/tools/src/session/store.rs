//! The store of each open binary: its history and its project on disk (design Section 3.10).
//!
//! A session with a projects root keeps one project directory per binary. A session without
//! one keeps the history in memory and a checkpoint copy of the program for reloads.
//!
//! Every commit of a tool goes through [`Session::transact`] or [`Session::undo`]:
//!
//! 1. The transaction commits in memory.
//! 2. The journal gets one line, and the line syncs.
//! 3. The history records the line.
//!
//! A failed journal write reloads the durable state, so memory and disk agree. A handler panic
//! writes a crash record and reloads the program from the snapshot and the journal (AC-148).

use std::path::PathBuf;

use ghidorah_base::{BinaryId, ErrorCode};
use ghidorah_db::project::check_root;
use ghidorah_db::{
    Commit, History, Line, MetaLine, Program, Project, ProjectError, RealFs, SessionLabel, Tx,
    TxLine, UndoError, UndoOutcome, UndoRequest,
};
use ghidorah_json::Value;

use super::Session;
use super::batch::BatchTx;
use crate::errors::{Candidate, ToolError};

/// The projects settings of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectsConfig {
    /// The projects root.
    pub root: PathBuf,
    /// `true` when `--project-root` names the root. A default root must be outside every git
    /// working tree (ADR-0022).
    pub named: bool,
    /// `true` replaces a stale lock.
    pub break_lock: bool,
}

impl ProjectsConfig {
    /// Checks the root by the rule of ADR-0022 on the real file system: a default root must be
    /// outside every git working tree. The check makes no directory.
    ///
    /// # Errors
    ///
    /// Returns the reason, in STE, when the rule refuses the root.
    pub fn check(&self) -> Result<(), String> {
        check_root(&mut RealFs, &self.root, self.named).map_err(|e| e.to_string())
    }
}

/// The history and the project of one open binary.
#[derive(Debug)]
pub struct Store {
    pub(super) history: History,
    pub(super) project: Option<Project>,
    pub(super) checkpoint: Option<Box<Program>>,
    pub(super) checkpoint_lines: usize,
    pub(super) batch: Option<Box<BatchTx>>,
    /// The reason why the binary has no project: the refusal of the projects root.
    pub(super) refusal: Option<String>,
}

impl Store {
    /// Makes the store of a binary with no project: the history and a checkpoint stay in
    /// memory.
    #[must_use]
    pub fn in_memory(program: &Program) -> Self {
        Self {
            history: History::new(),
            project: None,
            checkpoint: Some(Box::new(program.clone())),
            checkpoint_lines: 0,
            batch: None,
            refusal: None,
        }
    }

    /// Makes the store of a binary with a project.
    #[must_use]
    pub const fn on_disk(project: Project, history: History) -> Self {
        Self {
            history,
            project: Some(project),
            checkpoint: None,
            checkpoint_lines: 0,
            batch: None,
            refusal: None,
        }
    }

    /// Gives the history.
    #[must_use]
    pub const fn history(&self) -> &History {
        &self.history
    }

    /// Gives the project, or `None` for a binary with no project.
    #[must_use]
    pub const fn project(&self) -> Option<&Project> {
        self.project.as_ref()
    }

    /// Gives the reason why the binary has no project on disk, or `None`. Only a refused
    /// projects root gives a reason (ADR-0022).
    #[must_use]
    pub fn persist_reason(&self) -> Option<&str> {
        self.refusal.as_deref()
    }

    /// Puts a copy of `program` in place of the checkpoint of a store in memory.
    pub(super) fn checkpoint(&mut self, program: &Program) {
        if self.checkpoint.is_some() {
            self.checkpoint = Some(Box::new(program.clone()));
            self.checkpoint_lines = self.history.lines().len();
        }
    }
}

/// Gives the tool error of a project error.
pub(crate) fn project_error(error: &ProjectError) -> ToolError {
    let mut out = ToolError::new(error.code());
    match error {
        ProjectError::Locked { owner, stale } => {
            if let Some(owner) = owner {
                out = out.detail("owner", owner.to_json());
            }
            out = out.detail("stale", Value::Bool(*stale));
        }
        ProjectError::Corrupt { line } => {
            out = out.detail("line", Value::from(*line));
        }
        ProjectError::Replay(e) => {
            out = out.detail("line", Value::from(e.line));
        }
        ProjectError::Fs(_)
        | ProjectError::BadMeta(_)
        | ProjectError::Program(_)
        | ProjectError::InsideGitTree(_) => {
            out = out.detail("reason", Value::from(error.to_string()));
        }
        ProjectError::BadInput | ProjectError::Load(_) | ProjectError::ReadOnly => {}
    }
    out
}

/// Gives the tool error of an undo error.
pub(crate) fn undo_error(error: &UndoError) -> ToolError {
    let out = ToolError::new(error.code());
    match error {
        UndoError::Conflict { tx, later } => {
            out.detail("tx", Value::from(tx.to_string())).candidates(
                later
                    .iter()
                    .map(|t| Candidate::text(&t.to_string(), "tx"))
                    .collect(),
            )
        }
        UndoError::UserTx(tx) => out
            .detail("current", Value::from(tx.to_string()))
            .detail("source", Value::from("user")),
        UndoError::UnknownTx(_) => out.var("kind", "tx").detail("kind", Value::from("tx")),
        _ => out,
    }
}

impl Session {
    /// Gives the store of the open binary `id`.
    #[must_use]
    pub fn store(&self, id: BinaryId) -> Option<&Store> {
        self.stores.get(&id)
    }

    /// Gives the history of the open binary `id`.
    #[must_use]
    pub fn history(&self, id: BinaryId) -> Option<&History> {
        self.stores.get(&id).map(Store::history)
    }

    /// Runs `edit` in one transaction on the open binary `id`, commits it and writes its
    /// journal line. A no-op commit writes no line.
    ///
    /// `label` is the transaction label, for example the tool name. `session` is the session
    /// label of the call. The source is the source of the session settings.
    ///
    /// # Errors
    ///
    /// Returns `READ_ONLY_PROJECT` for a read-only binary, `INVALID_ARGUMENT` for a bad session
    /// label, the error of `edit`, or the error of a failed journal write. Then the program has
    /// the durable state.
    pub fn transact<T>(
        &mut self,
        id: BinaryId,
        label: &str,
        session: &str,
        edit: impl FnOnce(&mut Tx<'_>) -> Result<T, ToolError>,
    ) -> Result<(Commit, T), ToolError> {
        if self.in_batch(id) {
            return self.transact_batch(id, session, edit);
        }
        let session = session_label(session)?;
        let source = self.config.source;
        let binary = self
            .binaries
            .get_mut(&id)
            .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))?;
        if binary.read_only {
            return Err(ToolError::new(ErrorCode::ReadOnlyProject));
        }
        let mut tx = binary
            .program
            .begin(label, source, session)
            .map_err(|e| ToolError::new(e.code()))?;
        let value = edit(&mut tx)?;
        let commit = tx.commit().map_err(|e| ToolError::new(e.code()))?;
        if !commit.noop {
            self.journal(id, &TxLine::of_commit(&commit))?;
        }
        Ok((commit, value))
    }

    /// Runs one undo or redo request on the open binary `id` and writes its journal line.
    ///
    /// # Errors
    ///
    /// Returns `NOTHING_TO_UNDO`, `NOTHING_TO_REDO`, `CONFLICT`, `READ_ONLY_PROJECT` or the
    /// error of a failed journal write.
    pub fn undo(&mut self, id: BinaryId, req: &UndoRequest) -> Result<UndoOutcome, ToolError> {
        let (Some(binary), Some(store)) = (self.binaries.get_mut(&id), self.stores.get(&id)) else {
            return Err(ToolError::new(ErrorCode::UnknownBinary));
        };
        if binary.read_only && !req.dry_run {
            return Err(ToolError::new(ErrorCode::ReadOnlyProject));
        }
        let out = ghidorah_db::undo::run(&mut binary.program, &store.history, req)
            .map_err(|e| undo_error(&e))?;
        if let Some(line) = &out.line {
            self.journal(id, line)?;
        }
        Ok(out)
    }

    /// Writes a meta line for the open binary `id` and folds it into the program.
    ///
    /// # Errors
    ///
    /// Returns the error of a failed journal write.
    pub fn write_meta(&mut self, id: BinaryId, line: &MetaLine) -> Result<(), ToolError> {
        let (Some(binary), Some(store)) = (self.binaries.get_mut(&id), self.stores.get_mut(&id))
        else {
            return Err(ToolError::new(ErrorCode::UnknownBinary));
        };
        ghidorah_db::meta::apply(&mut binary.program, line);
        if let Some(batch) = store.batch.as_mut() {
            batch.fold(line);
        }
        if let Some(project) = store.project.as_mut().filter(|p| !p.is_read_only()) {
            project
                .append(&Line::Meta(line.clone()), &binary.program)
                .map_err(|e| project_error(&e))?;
        }
        store.history.record_meta(line);
        Ok(())
    }

    /// Writes one journal line of a commit and records it in the history.
    pub(super) fn journal(&mut self, id: BinaryId, line: &TxLine) -> Result<(), ToolError> {
        let (Some(binary), Some(store)) = (self.binaries.get(&id), self.stores.get_mut(&id)) else {
            return Err(ToolError::new(ErrorCode::UnknownBinary));
        };
        if let Some(project) = store.project.as_mut()
            && let Err(e) = project.append(&Line::Tx(Box::new(line.clone())), &binary.program)
        {
            let _ = self.reload(id);
            return Err(project_error(&e));
        }
        store.history.record(line);
        Ok(())
    }
}

/// Gives the session label of a call.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` for a label outside `[A-Za-z0-9._-]{1,64}`.
pub(crate) fn session_label(text: &str) -> Result<SessionLabel, ToolError> {
    SessionLabel::new(text).map_err(|_| {
        ToolError::new(ErrorCode::InvalidArgument)
            .var("field", "session")
            .path("/session")
            .detail(
                "expected",
                Value::from("1 to 64 bytes of A-Z, a-z, 0-9, ., _ and -"),
            )
    })
}
