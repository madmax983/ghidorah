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
//! [`Session::analyze_sliced`] and [`Session::reanalyze_sliced`] run the engine in fuel
//! slices with a progress report, a cancel check and a `max_ms` check per slice.
//!
//! An analysis run that commits gives one marker line per new revision. A complete run also
//! writes a snapshot, so a reopen needs no new run. A reopen compares the analysis inputs hash
//! of the last run with the hash of the program. A difference makes the state `stale`, and a
//! re-analysis from the start band 100 is due.

use std::path::{Path, PathBuf};

use ghidorah_base::{BinaryId, ErrorCode, Fuel, Rev, TxId, WarningCode};
use ghidorah_db::project::{Access, LoadSpec, OpenOptions, PROJECT_FILE, ProjectMeta, check_root};
use ghidorah_db::snapshot::{inputs_hash, result_hash};
use ghidorah_db::{Line, Project, ProjectError, ProjectSummary, RunLine, RunState};
use ghidorah_json::{Limits as JsonLimits, Object, Value};

use super::store::project_error;
use super::{OpenBinary, RunReport, Session, Store, Until};
use crate::api::Progress;
use crate::dispatch::Ctx;
use crate::envelope::{AnalysisInfo, AnalysisState, Warning};
use crate::errors::ToolError;
use crate::handlers::analysis_run::{SLICE_STEPS, SliceStop, Sliced};
use crate::handlers::load::spec_differs;

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

    /// Gives the open settings of a project of this session. `break_lock` replaces a stale
    /// lock for this open only. `--break-lock` does it for every open.
    fn open_options(&self, read_only: bool, break_lock: bool) -> OpenOptions {
        let break_lock = break_lock || self.config.projects.as_ref().is_some_and(|p| p.break_lock);
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
    /// on disk, but it makes no new project. `break_lock` replaces a stale lock for this call.
    ///
    /// # Errors
    ///
    /// Returns `PROJECT_LOCKED`, `JOURNAL_CORRUPT` or another project error. A project with
    /// other load settings than `load` gives `INVALID_ARGUMENT` with
    /// `details.reason: "load_spec_differs"`, and nothing opens.
    pub(crate) fn admit(
        &mut self,
        binary: OpenBinary,
        bytes: &[u8],
        load: LoadSpec,
        break_lock: bool,
    ) -> Result<(Admitted, Vec<Warning>), ToolError> {
        let root = match self.root_check() {
            Ok(Some(root)) => root,
            Ok(None) => return Ok(self.keep(binary, load, None)),
            // The binary stays in memory, and the store keeps the reason for the agent.
            Err(refusal) => return Ok(self.keep(binary, load, Some(refusal.to_string()))),
        };
        let dir = Project::dir_of(&root, binary.id);
        if Project::exists(self.fs.as_mut(), &dir) {
            return self.admit_project(&dir, binary.id, load, break_lock);
        }
        if binary.read_only {
            // A read-only session makes no new project.
            return Ok(self.keep(binary, load, None));
        }
        let meta = ProjectMeta::new(&binary.program, &binary.file_name, load);
        let opts = self.open_options(false, break_lock);
        let made = Project::create(self.fs.boxed(), &root, meta, bytes, &binary.program, &opts);
        let project = match made {
            Ok(project) => project,
            // Another process can make the project after the check above. Then the project
            // opens like a project that was there first.
            Err(_) if Project::exists(self.fs.as_mut(), &dir) => {
                return self.admit_project(&dir, binary.id, load, break_lock);
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

    /// Opens `binary` in memory with its load settings. `refusal` is the reason of a refused
    /// projects root.
    fn keep(
        &mut self,
        binary: OpenBinary,
        load: LoadSpec,
        refusal: Option<String>,
    ) -> (Admitted, Vec<Warning>) {
        let id = binary.id;
        self.open(binary);
        if let Some(store) = self.stores.get_mut(&id) {
            store.load = Some(load);
            store.refusal = refusal;
        }
        (Admitted::Fresh, Vec::new())
    }

    /// Opens the project of `id` in `dir` for a load with the settings `load`. The project
    /// keeps the settings of its first load, so other settings open nothing.
    fn admit_project(
        &mut self,
        dir: &Path,
        id: BinaryId,
        load: LoadSpec,
        break_lock: bool,
    ) -> Result<(Admitted, Vec<Warning>), ToolError> {
        let stored = self
            .fs
            .read(&dir.join(PROJECT_FILE))
            .ok()
            .and_then(|bytes| ghidorah_json::parse_bytes(&bytes, &JsonLimits::DEFAULT).ok())
            .and_then(|value| ProjectMeta::from_json(&value).ok())
            .map(|meta| meta.load);
        if let Some(stored) = stored.filter(|s| *s != load) {
            return Err(spec_differs(id, stored, load));
        }
        self.reopen_with(id, break_lock)?
            .ok_or_else(|| ToolError::new(ErrorCode::UnknownBinary))
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
        self.reopen_with(id, false)
    }

    /// Opens the project of `id` like [`Session::reopen`]. `break_lock` replaces a stale lock
    /// for this open only.
    ///
    /// # Errors
    ///
    /// Returns `PROJECT_LOCKED`, `JOURNAL_CORRUPT` or another project error.
    pub(crate) fn reopen_with(
        &mut self,
        id: BinaryId,
        break_lock: bool,
    ) -> Result<Option<(Admitted, Vec<Warning>)>, ToolError> {
        let Some(root) = self.projects_root() else {
            return Ok(None);
        };
        let dir = Project::dir_of(&root, id);
        if !Project::exists(self.fs.as_mut(), &dir) {
            return Ok(None);
        }
        let read_only = self.config.read_only;
        let opts = self.open_options(read_only, break_lock);
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

    /// Runs the analysis of the open binary `id` until `until` in the fuel slices of the call
    /// `ctx` (design Section 2.4). Gives `None` when the session has no engine or no such
    /// binary.
    ///
    /// A slice has [`SLICE_STEPS`] work units or a quarter of the units so far, whichever is
    /// more. Each slice with work sends one progress report. After each slice the run can
    /// stop. It stops when the analysis is complete, the slice does no work, the fuel is
    /// empty, the client cancels, or the `max_ms` guard fires. A time stop adds
    /// `W_TIME_STOP`. Eval mode turns the time guard off.
    ///
    /// # Errors
    ///
    /// Returns the error of the engine.
    pub fn analyze_sliced(
        &mut self,
        id: BinaryId,
        until: Until,
        ctx: &mut Ctx,
    ) -> Result<Option<Sliced>, ToolError> {
        self.sliced(id, None, until, ctx)
    }

    /// Runs the re-analysis of the open binary `id` from the start band `band` with the
    /// checkpoints of [`Session::analyze_sliced`]. With no engine, the analysis state becomes
    /// `stale`.
    ///
    /// # Errors
    ///
    /// Returns the error of the engine.
    pub fn reanalyze_sliced(
        &mut self,
        id: BinaryId,
        band: u16,
        ctx: &mut Ctx,
    ) -> Result<Option<Sliced>, ToolError> {
        self.sliced(id, Some(band), Until::Full, ctx)
    }

    /// Starts the re-analysis after an analysis-affecting commit like [`Session::after_edit`],
    /// with the checkpoints of [`Session::analyze_sliced`].
    ///
    /// # Errors
    ///
    /// Returns the error of the engine.
    pub fn after_edit_sliced(
        &mut self,
        id: BinaryId,
        band: Option<u16>,
        ctx: &mut Ctx,
    ) -> Result<Option<RunReport>, ToolError> {
        let Some(band) = band else {
            return Ok(None);
        };
        if self.batch_band(id, band) {
            return Ok(None);
        }
        Ok(self.reanalyze_sliced(id, band, ctx)?.map(|s| s.report()))
    }

    /// Tells if the `max_ms` guard of a call fires: the work started at the monotonic time
    /// `began` of the session clock. Eval mode turns the guard off (design Section 10.11).
    #[must_use]
    pub fn past_max_ms(&self, began: u64, max_ms: Option<u64>) -> bool {
        !self.config.run.eval_mode
            && max_ms.is_some_and(|ms| self.clock.monotonic_ms().saturating_sub(began) > ms)
    }

    /// Runs the slices of [`Session::analyze_sliced`]. A start band makes the first slice a
    /// re-analysis. The next slices resume the run of the engine.
    fn sliced(
        &mut self,
        id: BinaryId,
        band: Option<u16>,
        until: Until,
        ctx: &mut Ctx,
    ) -> Result<Option<Sliced>, ToolError> {
        let began = self.clock.monotonic_ms();
        let mut out: Option<Sliced> = None;
        loop {
            let used = out.map_or(0, |s| s.steps_used);
            let mut fuel = Fuel::new(SLICE_STEPS.max(used / 4).min(ctx.fuel.remaining()));
            let report = match (out, band) {
                (None, Some(band)) => self.reanalyze(id, band, &mut fuel)?,
                _ => self.analyze(id, until, &mut fuel)?,
            };
            let Some(report) = report else {
                return Ok(out);
            };
            let _ = ctx.fuel.take(report.steps_used.min(ctx.fuel.remaining()));
            let total = used.saturating_add(report.steps_used);
            let mut run = Sliced {
                state: report.state,
                steps_used: total,
                stop: None,
                idle: report.steps_used == 0,
            };
            if !run.idle {
                ctx.progress(Progress {
                    progress: total,
                    total: None,
                    message: format!("The analysis used {total} work units."),
                });
            }
            let done = run.state == AnalysisState::Complete || run.idle;
            if !done && ctx.cancelled() {
                run.stop = Some(SliceStop::Cancel);
            } else if !done && self.past_max_ms(began, ctx.max_ms) {
                run.stop = Some(SliceStop::Time);
                ctx.warn(Warning::new(WarningCode::TimeStop));
            }
            out = Some(run);
            if done || run.stop.is_some() || ctx.fuel.remaining() == 0 {
                return Ok(out);
            }
        }
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
}
