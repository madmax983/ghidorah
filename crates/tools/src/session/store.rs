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

use std::path::{Path, PathBuf};

use ghidorah_base::{BinaryId, ErrorCode};
use ghidorah_db::project::{LoadSpec, check_root};
use ghidorah_db::{
    Commit, FsError, History, Line, MetaLine, Program, Project, ProjectError, RealFs, SessionLabel,
    Tx, TxLine, UndoError, UndoOutcome, UndoRequest,
};
use ghidorah_json::Value;

use super::Session;
use super::batch::BatchTx;
use crate::dispatch::Crash;
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
    /// Returns the reason, in STE, when the rule refuses the root. The reason names no path.
    pub fn check(&self) -> Result<(), String> {
        check_root(&mut RealFs, &self.root, self.named).map_err(|e| project_reason(&e, None))
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
    /// The load settings of the first load of a binary in memory.
    pub(super) load: Option<LoadSpec>,
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
            load: None,
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
            load: None,
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

    /// Gives how the loader read the binary: the load settings of the project, else those of
    /// the first load of a binary in memory. Gives `None` when the session does not know them.
    #[must_use]
    pub fn load_spec(&self) -> Option<LoadSpec> {
        self.project.as_ref().map(|p| p.meta().load).or(self.load)
    }

    /// Puts a copy of `program` in place of the checkpoint of a store in memory.
    pub(super) fn checkpoint(&mut self, program: &Program) {
        if self.checkpoint.is_some() {
            self.checkpoint = Some(Box::new(program.clone()));
            self.checkpoint_lines = self.history.lines().len();
        }
    }
}

/// The reason of a default projects root inside a git working tree (ADR-0022). It names no
/// path, because no output holds the projects root (design Section 10.11).
const IN_GIT_TREE: &str = "The default projects root is inside a git working tree, so no project persists. Send --project-root DIR, or set XDG_DATA_HOME to a directory outside the git working tree.";

/// Gives the reason of a project error in STE. The reason holds no absolute path (design
/// Section 10.11). A file error names its path relative to the project directory `dir`, or
/// no path when the file is not in `dir`.
pub(crate) fn project_reason(error: &ProjectError, dir: Option<&Path>) -> String {
    match error {
        ProjectError::InsideGitTree(_) => IN_GIT_TREE.to_owned(),
        ProjectError::Fs(e) => fs_reason(e, dir),
        _ => error.to_string(),
    }
}

/// Gives the reason of a file error with the path relative to the project directory `dir`.
fn fs_reason(error: &FsError, dir: Option<&Path>) -> String {
    // The relative path with a space before it, or an empty text.
    let rel = |path: &Path| {
        dir.and_then(|d| path.strip_prefix(d).ok())
            .filter(|rel| !rel.as_os_str().is_empty())
            .map(|rel| format!(" {}", rel.display()))
            .unwrap_or_default()
    };
    match error {
        FsError::NotFound(p) => format!("The project file{} does not exist.", rel(p)),
        FsError::Exists(p) => format!("The project file{} exists already.", rel(p)),
        FsError::Io { op, path, message } => {
            format!(
                "The operation {op} on the project file{} fails: {message}",
                rel(path)
            )
        }
        FsError::WrongKind(p) => format!(
            "The project file{} is a symbolic link or an entry of the wrong kind.",
            rel(p)
        ),
        FsError::Stopped => error.to_string(),
    }
}

/// Gives the tool error of a project error. `dir` is the project directory, when it is
/// known. The reason in the details names no absolute path.
pub(crate) fn project_error(error: &ProjectError, dir: Option<&Path>) -> ToolError {
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
            out = out.detail("reason", Value::from(project_reason(error, dir)));
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
                .map_err(|e| project_error(&e, Some(project.dir())))?;
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
            let error = project_error(&e, Some(project.dir()));
            let _ = self.reload(id);
            return Err(error);
        }
        store.history.record(line);
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
            let loaded = project
                .load(&limits)
                .map_err(|e| project_error(&e, Some(project.dir())))?;
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
