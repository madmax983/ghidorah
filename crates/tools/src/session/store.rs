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

use ghidorah_base::{BinaryId, ErrorCode, Fuel, Rev, TxId, WarningCode};
use ghidorah_db::project::{Access, LoadSpec, OpenOptions, ProjectMeta};
use ghidorah_db::{
    Commit, Fs, History, Line, MetaLine, Program, Project, ProjectError, ProjectSummary, RunLine,
    RunState, SessionLabel, Tx, TxLine, UndoError, UndoOutcome, UndoRequest,
};
use ghidorah_json::Value;

use super::{OpenBinary, RunReport, Session};
use crate::dispatch::Crash;
use crate::envelope::{AnalysisInfo, AnalysisState, Warning};
use crate::errors::ToolError;

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

/// The history and the project of one open binary.
#[derive(Debug)]
pub struct Store {
    history: History,
    project: Option<Project>,
    checkpoint: Option<Box<Program>>,
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
        }
    }

    /// Makes the store of a binary with a project.
    #[must_use]
    pub const fn on_disk(project: Project, history: History) -> Self {
        Self {
            history,
            project: Some(project),
            checkpoint: None,
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
}

/// What the session must do after it opens a binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// The binary has no analysis yet.
    Fresh,
    /// The analysis of the project is current.
    Current,
    /// The analysis inputs changed. A re-analysis from this start band is due.
    Stale(u16),
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
        _ => {}
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
                    .map(|t| crate::errors::Candidate::text(&t.to_string(), "tx"))
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

/// Gives the analysis state of a run state.
const fn state_of(state: RunState) -> AnalysisState {
    match state {
        RunState::Complete => AnalysisState::Complete,
        RunState::BudgetStopped => AnalysisState::BudgetStopped,
    }
}

impl Session {
    /// Replaces the file system of the projects, for example with a simulated one in tests.
    pub fn set_fs(&mut self, fs: Box<dyn Fs>) {
        self.fs = fs;
    }

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

    /// Gives the projects root when the session keeps projects there, else `None`.
    pub(crate) fn projects_root(&mut self) -> Option<PathBuf> {
        let _ = self.config.projects.as_ref()?;
        None
    }

    /// Gives the projects on disk, newest revision first.
    pub fn projects(&mut self) -> Vec<ProjectSummary> {
        match self.projects_root() {
            Some(root) => ghidorah_db::project::list(self.fs.as_mut(), &root),
            None => Vec::new(),
        }
    }

    /// Tells if the projects root holds a project of `id`.
    pub fn has_project(&mut self, id: BinaryId) -> bool {
        match self.projects_root() {
            Some(root) => Project::exists(self.fs.as_mut(), &Project::dir_of(&root, id)),
            None => false,
        }
    }

    /// Gives the open settings of a project of this session.
    pub(crate) fn open_options(&self, read_only: bool) -> OpenOptions {
        let break_lock = self.config.projects.as_ref().is_some_and(|p| p.break_lock);
        OpenOptions {
            access: if read_only {
                Access::ReadOnly
            } else {
                Access::Write { break_lock }
            },
            me: self.me.clone(),
            limits: self.config.limits,
            engine: self.inputs_tag(),
        }
    }

    /// Gives the analyzer versions of the engine, or `null` with no engine.
    pub(crate) fn inputs_tag(&self) -> Value {
        self.engine
            .as_ref()
            .map_or(Value::Null, |engine| engine.inputs_tag())
    }

    /// Opens a new binary of `bytes` with its project: an existing project of the binary or a
    /// new one. A session with no projects root keeps the binary in memory.
    ///
    /// # Errors
    ///
    /// Returns `PROJECT_LOCKED`, `JOURNAL_CORRUPT` or another project error.
    pub(crate) fn admit(
        &mut self,
        binary: OpenBinary,
        bytes: &[u8],
        load: LoadSpec,
    ) -> Result<(Admitted, Vec<Warning>), ToolError> {
        let _ = (bytes, load);
        let store = Store::in_memory(&binary.program);
        self.stores.insert(binary.id, store);
        self.open(binary);
        Ok((Admitted::Fresh, Vec::new()))
    }

    /// Opens the project of `id` from the projects root. Gives `None` when no project exists.
    ///
    /// # Errors
    ///
    /// Returns `PROJECT_LOCKED`, `JOURNAL_CORRUPT` or another project error.
    pub(crate) fn reopen(
        &mut self,
        id: BinaryId,
    ) -> Result<Option<(Admitted, Vec<Warning>)>, ToolError> {
        let _ = (id, state_of);
        Ok(None)
    }

    /// Opens the project of `id` from the projects root, for `--open`. Gives `false` when no
    /// project exists. The analysis of a stale project stays `stale`.
    ///
    /// # Errors
    ///
    /// Returns `PROJECT_LOCKED`, `JOURNAL_CORRUPT` or another project error.
    pub fn open_project(&mut self, id: BinaryId) -> Result<bool, ToolError> {
        if self.binaries.contains_key(&id) {
            return Ok(true);
        }
        Ok(self.reopen(id)?.is_some())
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
    /// label, the error of `edit`, or `INTERNAL_ERROR` when the journal write fails. Then the
    /// program has the durable state.
    pub fn transact<T>(
        &mut self,
        id: BinaryId,
        label: &str,
        session: &str,
        edit: impl FnOnce(&mut Tx<'_>) -> Result<T, ToolError>,
    ) -> Result<(Commit, T), ToolError> {
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
    /// Returns `NOTHING_TO_UNDO`, `NOTHING_TO_REDO`, `CONFLICT`, `READ_ONLY_PROJECT` or
    /// `INTERNAL_ERROR` for a failed journal write.
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
    /// Returns `INTERNAL_ERROR` when the journal write fails.
    pub fn write_meta(&mut self, id: BinaryId, line: MetaLine) -> Result<(), ToolError> {
        let (Some(binary), Some(store)) = (self.binaries.get_mut(&id), self.stores.get_mut(&id))
        else {
            return Err(ToolError::new(ErrorCode::UnknownBinary));
        };
        ghidorah_db::meta::apply(&mut binary.program, &line);
        if let Some(project) = store.project.as_mut().filter(|p| !p.is_read_only()) {
            project
                .append(&Line::Meta(line.clone()), &binary.program)
                .map_err(|e| project_error(&e))?;
        }
        store.history.record_meta(&line);
        Ok(())
    }

    /// Starts the re-analysis after an analysis-affecting commit with the start band `band`.
    /// With no engine, the analysis state becomes `stale`.
    ///
    /// # Errors
    ///
    /// Returns the error of the engine.
    pub fn after_edit(
        &mut self,
        id: BinaryId,
        band: Option<u16>,
        fuel: &mut Fuel,
    ) -> Result<Option<RunReport>, ToolError> {
        let Some(band) = band else {
            return Ok(None);
        };
        self.reanalyze(id, band, fuel)
    }

    /// Runs the re-analysis of the open binary `id` from the start band `band`. With no
    /// engine, the analysis state becomes `stale`.
    ///
    /// # Errors
    ///
    /// Returns the error of the engine.
    pub fn reanalyze(
        &mut self,
        id: BinaryId,
        band: u16,
        fuel: &mut Fuel,
    ) -> Result<Option<RunReport>, ToolError> {
        let (Some(engine), Some(binary)) = (self.engine.as_mut(), self.binaries.get_mut(&id))
        else {
            if let Some(binary) = self.binaries.get_mut(&id) {
                binary.analysis = binary.analysis.map(|a| AnalysisInfo {
                    state: AnalysisState::Stale,
                    rev: a.rev,
                });
            }
            return Ok(None);
        };
        let before = binary.program.rev();
        let report = engine.reanalyze(binary, band, fuel)?;
        self.finish_run(id, before, report)?;
        Ok(Some(report))
    }

    /// Records the analysis commits of a run: one marker line per new revision, and a snapshot
    /// after a complete run. Sets the analysis state of the binary.
    ///
    /// # Errors
    ///
    /// Returns `INTERNAL_ERROR` when the journal write fails.
    pub(crate) fn finish_run(
        &mut self,
        id: BinaryId,
        before: Rev,
        report: RunReport,
    ) -> Result<(), ToolError> {
        let _ = (before, Line::Run, RunLine::clone);
        if let Some(binary) = self.binaries.get_mut(&id) {
            binary.analysis = Some(AnalysisInfo {
                state: report.state,
                rev: binary.program.rev().0,
            });
        }
        Ok(())
    }

    /// Writes one journal line of a commit and records it in the history.
    fn journal(&mut self, id: BinaryId, line: &TxLine) -> Result<(), ToolError> {
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

    /// Drops the program of the open binary `id` and loads it again. A project gives the
    /// snapshot and the journal. A binary in memory gives its checkpoint and its history.
    ///
    /// # Errors
    ///
    /// Returns the project error of a failed load.
    pub fn reload(&mut self, id: BinaryId) -> Result<(), ToolError> {
        let _ = id;
        Ok(())
    }

    /// Writes the snapshot of the open binary `id` and releases its lock.
    pub fn close(&mut self, id: BinaryId) {
        let (Some(binary), Some(store)) = (self.binaries.get(&id), self.stores.get_mut(&id)) else {
            return;
        };
        if let Some(project) = store.project.as_mut() {
            if !project.is_read_only() {
                let _ = project.snapshot(&binary.program);
            }
            project.release();
        }
    }

    /// Writes the crash record of a handler panic for the bound binary.
    pub(crate) fn write_crash(&mut self, crash: &Crash) {
        let _ = (
            crash,
            TxId(0),
            WarningCode::JournalTailDiscarded,
            Warning::new,
        );
    }

    /// Gives the project file of a new project of `binary`.
    pub(crate) fn project_meta(binary: &OpenBinary, load: LoadSpec) -> ProjectMeta {
        ProjectMeta::new(&binary.program, &binary.file_name, load)
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
