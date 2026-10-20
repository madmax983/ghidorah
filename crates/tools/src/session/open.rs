//! The binaries of a session: their projects on disk and their analysis markers (design
//! Sections 3.9 and 3.10).
//!
//! | Step | Effect |
//! |---|---|
//! | [`Session::admit`] | a new binary: its project on disk opens, or a new project starts |
//! | [`Session::reopen`] | the project of a `binary_id` opens from the projects root |
//! | [`Session::reload`] | the program loads again from the project or the checkpoint |
//! | [`Session::close`] | a snapshot, and the lock goes |
//!
//! An analysis run that commits gives one marker line per new revision. A complete run also
//! writes a snapshot, so a reopen needs no new run. A reopen compares the analysis inputs hash
//! of the last run with the hash of the program. A difference makes the state `stale`, and a
//! re-analysis from the start band 100 is due.

use std::path::PathBuf;

use ghidorah_base::{BinaryId, ErrorCode, Fuel, Rev, TxId, WarningCode};
use ghidorah_db::project::{Access, LoadSpec, OpenOptions, ProjectMeta, check_root};
use ghidorah_db::snapshot::{inputs_hash, result_hash};
use ghidorah_db::{Line, Project, ProjectError, ProjectSummary, RunLine, RunState};
use ghidorah_json::{Object, Value};

use super::store::project_error;
use super::{OpenBinary, RunReport, Session, Store};
use crate::dispatch::Crash;
use crate::envelope::{AnalysisInfo, AnalysisState, Warning};
use crate::errors::ToolError;

/// The start band of a full re-analysis (design Section 3.9).
pub const FULL_BAND: u16 = 100;

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

/// Gives the analysis state of a run state.
const fn state_of(state: RunState) -> AnalysisState {
    match state {
        RunState::Complete => AnalysisState::Complete,
        RunState::BudgetStopped => AnalysisState::BudgetStopped,
    }
}

impl Session {
    /// Makes a session of the shipped registry whose clock stays at `ms` milliseconds.
    ///
    /// The eval harness uses it: it has no clock of its own, and two runs must give
    /// byte-equal responses (design Section 12.4).
    #[must_use]
    pub fn fixed(mut config: super::SessionConfig, ms: u64) -> Self {
        config.run.fixed_time = Some(ms);
        Self::new(config, Box::new(ghidorah_base::FixedClock::new(ms)))
    }

    /// Replaces the file system of the projects, for example with a simulated one in tests.
    pub fn set_fs(&mut self, fs: Box<dyn ghidorah_db::Fs>) {
        self.fs = fs;
    }

    /// Checks the projects root of the session. Gives `None` for a session with no projects
    /// root, else the root.
    ///
    /// # Errors
    ///
    /// Returns the refusal of a default root inside a git working tree (ADR-0022).
    fn root_check(&mut self) -> Result<Option<PathBuf>, ProjectError> {
        let Some(cfg) = self.config.projects.as_ref() else {
            return Ok(None);
        };
        let (root, named) = (cfg.root.clone(), cfg.named);
        check_root(self.fs.as_mut(), &root, named)?;
        Ok(Some(root))
    }

    /// Gives the projects root when the session keeps projects there, else `None`.
    ///
    /// A default root inside a git working tree keeps no projects (ADR-0022).
    pub(crate) fn projects_root(&mut self) -> Option<PathBuf> {
        self.root_check().ok().flatten()
    }

    /// Gives the reason why the session keeps its binaries in memory only: the text of the
    /// refusal of its projects root. Gives `None` when the root keeps projects, or when the
    /// session has no projects root.
    pub fn persist_refusal(&mut self) -> Option<String> {
        self.root_check().err().map(|e| e.to_string())
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
    fn open_options(&self, read_only: bool) -> OpenOptions {
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
    fn inputs_tag(&self) -> Value {
        self.engine
            .as_ref()
            .map_or(Value::Null, |engine| engine.inputs_tag())
    }

    /// Opens a new binary of `bytes` with its project: the project of the binary on disk, or a
    /// new one. A session with no projects root keeps the binary in memory. A refused root also
    /// keeps it in memory, and the store keeps the reason. A read-only session opens a project
    /// on disk, but it makes no new project.
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
        let root = match self.root_check() {
            Ok(Some(root)) => root,
            Ok(None) => {
                self.open(binary);
                return Ok((Admitted::Fresh, Vec::new()));
            }
            Err(refusal) => {
                // The binary stays in memory, and the store keeps the reason for the agent.
                let id = binary.id;
                self.open(binary);
                if let Some(store) = self.stores.get_mut(&id) {
                    store.refusal = Some(refusal.to_string());
                }
                return Ok((Admitted::Fresh, Vec::new()));
            }
        };
        if Project::exists(self.fs.as_mut(), &Project::dir_of(&root, binary.id)) {
            return self
                .reopen(binary.id)?
                .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary));
        }
        if binary.read_only {
            // A read-only session makes no new project.
            self.open(binary);
            return Ok((Admitted::Fresh, Vec::new()));
        }
        let meta = ProjectMeta::new(&binary.program, &binary.file_name, load);
        let opts = self.open_options(false);
        let made = Project::create(self.fs.boxed(), &root, meta, bytes, &binary.program, &opts);
        let project = match made {
            Ok(project) => project,
            // Another process can make the project after the check above. Then the project
            // opens like a project that was there first.
            Err(_) if Project::exists(self.fs.as_mut(), &Project::dir_of(&root, binary.id)) => {
                return self
                    .reopen(binary.id)?
                    .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary));
            }
            Err(error) => return Err(project_error(&error)),
        };
        self.stores.insert(
            binary.id,
            Store::on_disk(project, ghidorah_db::History::new()),
        );
        self.open(binary);
        Ok((Admitted::Fresh, Vec::new()))
    }

    /// Opens the project of `id` from the projects root. Gives `None` when no project exists.
    ///
    /// The label of the binary counts the distinct `mcp-` labels of its journal.
    ///
    /// # Errors
    ///
    /// Returns `PROJECT_LOCKED`, `JOURNAL_CORRUPT` or another project error.
    pub(crate) fn reopen(
        &mut self,
        id: BinaryId,
    ) -> Result<Option<(Admitted, Vec<Warning>)>, ToolError> {
        let Some(root) = self.projects_root() else {
            return Ok(None);
        };
        let dir = Project::dir_of(&root, id);
        if !Project::exists(self.fs.as_mut(), &dir) {
            return Ok(None);
        }
        let read_only = self.config.read_only;
        let opts = self.open_options(read_only);
        let opened = Project::open(self.fs.boxed(), &dir, &opts).map_err(|e| project_error(&e))?;
        let status = opened.analysis;
        let analysis = status.last_run.map(|run| AnalysisInfo {
            state: if status.current {
                state_of(run.state)
            } else {
                AnalysisState::Stale
            },
            rev: run.rev.0,
        });
        let admitted = match (status.last_run, status.current) {
            (None, _) => Admitted::Fresh,
            (Some(_), true) => Admitted::Current,
            (Some(_), false) => Admitted::Stale(FULL_BAND),
        };
        let mut warnings = Vec::new();
        if opened.tail_discarded {
            warnings.push(Warning::new(WarningCode::JournalTailDiscarded));
        }
        let binary = OpenBinary {
            id,
            program: opened.program,
            file_name: opened.project.meta().file_name.clone(),
            read_only,
            label: self.config.labels.label(opened.history.mcp_labels()),
            analysis,
        };
        self.stores
            .insert(id, Store::on_disk(opened.project, opened.history));
        self.open(binary);
        Ok(Some((admitted, warnings)))
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
        if self.batch_band(id, band) {
            return Ok(None);
        }
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
    /// Returns the error of a failed journal write.
    pub(crate) fn finish_run(
        &mut self,
        id: BinaryId,
        before: Rev,
        report: RunReport,
    ) -> Result<(), ToolError> {
        let tag = self.inputs_tag();
        let (Some(binary), Some(store)) = (self.binaries.get_mut(&id), self.stores.get_mut(&id))
        else {
            return Ok(());
        };
        let program = &binary.program;
        let after = program.rev();
        let config = store.project.as_ref().map_or_else(
            || Value::Object(Object::new()),
            |p| p.meta().analysis_config.clone(),
        );
        let inputs = inputs_hash(program, &tag, &config);
        let result = result_hash(program.analysis());
        let state = match report.state {
            AnalysisState::Complete => RunState::Complete,
            AnalysisState::BudgetStopped | AnalysisState::Stale => RunState::BudgetStopped,
        };
        let last_tx = program.last_tx().0;
        let mut rev = before.0;
        // Each pass writes the marker of one new revision.
        while rev < after.0 {
            rev = rev.saturating_add(1);
            let line = RunLine {
                rev: Rev(rev),
                tx: TxId(last_tx.saturating_sub(after.0.saturating_sub(rev))),
                state,
                inputs_hash: inputs,
                fuel_used: if rev == after.0 { report.steps_used } else { 0 },
                result_hash: result,
            };
            if let Some(project) = store.project.as_mut().filter(|p| !p.is_read_only()) {
                project
                    .append(&Line::Run(line), program)
                    .map_err(|e| project_error(&e))?;
            }
            store.history.record_run(&line);
        }
        if after > before {
            if let (RunState::Complete, Some(project)) =
                (state, store.project.as_mut().filter(|p| !p.is_read_only()))
            {
                project.snapshot(program).map_err(|e| project_error(&e))?;
            }
            store.checkpoint(program);
        }
        binary.analysis = Some(AnalysisInfo {
            state: report.state,
            rev: after.0,
        });
        Ok(())
    }

    /// Drops the program of the open binary `id` and loads it again. A project gives the
    /// snapshot and the journal. A binary in memory gives its checkpoint and its history.
    ///
    /// # Errors
    ///
    /// Returns the project error of a failed load, or `INTERNAL_ERROR` when the history does not
    /// replay over the checkpoint.
    pub fn reload(&mut self, id: BinaryId) -> Result<(), ToolError> {
        let limits = self.config.limits;
        let (Some(binary), Some(store)) = (self.binaries.get_mut(&id), self.stores.get_mut(&id))
        else {
            return Ok(());
        };
        if let Some(project) = store.project.as_mut() {
            let loaded = project.load(&limits).map_err(|e| project_error(&e))?;
            binary.program = loaded.program;
            store.history = loaded.history;
            return Ok(());
        }
        let Some(checkpoint) = &store.checkpoint else {
            return Ok(());
        };
        let mut program = (**checkpoint).clone();
        let tail = store
            .history
            .lines()
            .get(store.checkpoint_lines..)
            .unwrap_or_default();
        for line in tail {
            match line {
                Line::Tx(t) => ghidorah_db::replay::apply_tx(&mut program, t)
                    .map_err(|_| ToolError::new(ErrorCode::InternalError))?,
                Line::Meta(m) => ghidorah_db::meta::apply(&mut program, m),
                Line::Run(_) => {}
            }
        }
        binary.program = program;
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

    /// Writes the crash record of a handler panic for the bound binary: the tool, the
    /// arguments, the rev and the panic text.
    pub(crate) fn write_crash(&mut self, crash: &Crash) {
        let Some(id) = self.current else {
            return;
        };
        let rev = self.binaries.get(&id).map_or(0, |b| b.program.rev().0);
        let record = Value::object([
            ("tool", Value::from(crash.tool.as_str())),
            ("args", Value::from(crash.args.as_str())),
            ("rev", Value::from(rev)),
            ("panic", Value::from(crash.panic.as_str())),
        ]);
        let project = self
            .stores
            .get_mut(&id)
            .and_then(|s| s.project.as_mut())
            .filter(|p| !p.is_read_only());
        if let Some(project) = project {
            let _ = project.write_crash(&crash.id, &record);
        }
    }
}
