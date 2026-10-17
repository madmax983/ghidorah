//! The project directory: the persistent state of one binary (design Section 3.10, ADR-0022).
//!
//! ```text
//! <projects_root>/<binary_id>/
//!   .gitignore      "*"
//!   project.json    {format_version, binary_id, sha256, file_name, load, analysis_config, ghidorah_version}
//!   bin/<sha256>    the input copy, mode 0444
//!   journal.jsonl   one line per commit, see crate::journal
//!   snapshot.json   see crate::snapshot
//!   project.lock    see crate::lock
//!   crash/<id>.json one crash record per handler panic
//! ```
//!
//! [`Project::open`] follows the open flow of Section 3.10: lock, `project.json`, the input
//! hash, the snapshot, replay, the torn tail and the analysis inputs hash. A torn last line
//! goes out of the journal with a new journal file in a write open (`W_JOURNAL_TAIL_DISCARDED`).
//! A bad line in the middle gives `JOURNAL_CORRUPT` with its line number.
//!
//! [`Project::append`] writes one line and syncs it. After every [`SNAPSHOT_EVERY`] lines it
//! also writes a snapshot.

mod disk;
mod roots;

#[cfg(test)]
pub(crate) mod tests;

use std::fmt;
use std::path::{Path, PathBuf};

use ghidorah_base::{BinaryId, ErrorCode, Limits, hex, sha256};
use ghidorah_json::Value;
use ghidorah_loader::LoadOpts;

use crate::fs::{Fs, FsError};
use crate::history::History;
use crate::journal::{JOURNAL_FILE, Line, RunLine};
use crate::lock::{self, LockInfo};
use crate::program::Program;
use crate::replay::ReplayError;
use crate::snapshot::{self, FORMAT_VERSION};

pub use roots::{ProjectSummary, check_root, inside_git_tree, list};

/// The file name of the project file.
pub const PROJECT_FILE: &str = "project.json";

/// The file name of the temporary project file.
pub const PROJECT_TMP: &str = "project.json.tmp";

/// The file name of the temporary journal of a tail repair.
pub const JOURNAL_TMP: &str = "journal.jsonl.tmp";

/// The file name of the ignore file.
pub const GITIGNORE_FILE: &str = ".gitignore";

/// The text of the ignore file: ignore every file of the directory.
pub const GITIGNORE_TEXT: &str = "*\n";

/// The directory of the input copy.
pub const BIN_DIR: &str = "bin";

/// The directory of the crash records.
pub const CRASH_DIR: &str = "crash";

/// The number of journal lines between two snapshots.
pub const SNAPSHOT_EVERY: u64 = 256;

/// The version of the program that writes a project.
pub const GHIDORAH_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How the loader reads the input copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadSpec {
    /// The probe finds the format.
    Auto,
    /// A raw blob of x86-64 code.
    Raw {
        /// The load address.
        base: u64,
        /// The entry address, or `None`.
        entry: Option<u64>,
    },
}

impl LoadSpec {
    /// Gives the loader options.
    #[must_use]
    pub fn opts(&self) -> LoadOpts {
        match *self {
            Self::Auto => LoadOpts::AUTO,
            Self::Raw { base, entry } => LoadOpts::raw(base, entry),
        }
    }
}

/// The content of `project.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectMeta {
    /// The format version: [`FORMAT_VERSION`].
    pub format_version: u64,
    /// The binary ID.
    pub binary_id: BinaryId,
    /// The SHA-256 of the input.
    pub sha256: [u8; 32],
    /// The file name of the input.
    pub file_name: String,
    /// How the loader reads the input.
    pub load: LoadSpec,
    /// The analysis config. The analysis inputs hash reads it.
    pub analysis_config: Value,
    /// The version of the program that made the project.
    pub ghidorah_version: String,
}

impl ProjectMeta {
    /// Makes the project file of `program` with an empty analysis config.
    #[must_use]
    pub fn new(program: &Program, file_name: &str, load: LoadSpec) -> Self {
        let meta = program.meta();
        Self {
            format_version: FORMAT_VERSION,
            binary_id: meta.binary_id,
            sha256: meta.sha256,
            file_name: file_name.to_owned(),
            load,
            analysis_config: Value::Object(ghidorah_json::Object::new()),
            ghidorah_version: GHIDORAH_VERSION.to_owned(),
        }
    }

    /// Gives the JSON form.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let load = match self.load {
            LoadSpec::Auto => Value::object([("format", Value::from("auto"))]),
            LoadSpec::Raw { base, entry } => Value::object([
                ("format", Value::from("raw")),
                ("base", Value::from(hex::u64_text(base))),
                ("entry", entry.map(hex::u64_text).into()),
            ]),
        };
        Value::object([
            ("format_version", Value::from(self.format_version)),
            ("binary_id", Value::from(self.binary_id.to_string())),
            ("sha256", Value::from(hex::encode(&self.sha256))),
            ("file_name", Value::from(self.file_name.as_str())),
            ("load", load),
            ("analysis_config", self.analysis_config.clone()),
            (
                "ghidorah_version",
                Value::from(self.ghidorah_version.as_str()),
            ),
        ])
    }

    /// Reads the JSON form.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::BadMeta`] for a bad shape, another format version or a binary
    /// ID that is not the start of the SHA-256.
    pub fn from_json(value: &Value) -> Result<Self, ProjectError> {
        disk::meta_from_json(value)
    }
}

/// The access of an open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// One writer with the lock.
    Write {
        /// `true` replaces a stale lock.
        break_lock: bool,
    },
    /// A reader with no lock. The project accepts no edits.
    ReadOnly,
}

/// The settings of an open or a create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOptions {
    /// The access.
    pub access: Access,
    /// The lock owner of this process.
    pub me: LockInfo,
    /// The caps of the load.
    pub limits: Limits,
    /// The analyzer versions of the analysis inputs hash.
    pub engine: Value,
}

/// The analysis state of an opened project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AnalysisStatus {
    /// The last analysis run of the journal, or `None`.
    pub last_run: Option<RunLine>,
    /// An analysis run after the snapshot changed the analysis layer. The layer is behind.
    pub behind: bool,
    /// The last run has the analysis inputs hash of the program, and the layer is not behind.
    pub current: bool,
}

/// The state of a project that [`Project::load`] reads.
#[derive(Debug)]
pub struct Loaded {
    /// The program after the snapshot and the replay.
    pub program: Program,
    /// The history of all journal lines.
    pub history: History,
    /// The load dropped a torn last line.
    pub tail_discarded: bool,
    /// The analysis state.
    pub analysis: AnalysisStatus,
}

/// An opened project.
#[derive(Debug)]
pub struct Opened {
    /// The project.
    pub project: Project,
    /// The program after the snapshot and the replay.
    pub program: Program,
    /// The history of all journal lines.
    pub history: History,
    /// The open dropped a torn last line.
    pub tail_discarded: bool,
    /// The analysis state.
    pub analysis: AnalysisStatus,
}

/// The error of a project operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectError {
    /// A file operation failed.
    Fs(FsError),
    /// Another writer holds the lock: `PROJECT_LOCKED`.
    Locked {
        /// The owner of the lock, or `None` for a lock file that does not parse.
        owner: Option<LockInfo>,
        /// The owner is not alive.
        stale: bool,
    },
    /// A journal line in the middle is bad: `JOURNAL_CORRUPT`.
    Corrupt {
        /// The line number, from 1.
        line: usize,
    },
    /// The project file is bad.
    BadMeta(String),
    /// The input copy does not have the SHA-256 of the project file.
    BadInput,
    /// The loader refuses the input copy.
    Load(String),
    /// The program does not build.
    Program(String),
    /// The project is open in read-only mode: `READ_ONLY_PROJECT`.
    ReadOnly,
    /// A journal line does not replay.
    Replay(ReplayError),
    /// A default projects root inside a git working tree.
    InsideGitTree(PathBuf),
}

impl ProjectError {
    /// Gives the error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Locked { .. } => ErrorCode::ProjectLocked,
            Self::Corrupt { .. } | Self::Replay(_) => ErrorCode::JournalCorrupt,
            Self::ReadOnly => ErrorCode::ReadOnlyProject,
            Self::Fs(FsError::NotFound(_)) | Self::BadInput => ErrorCode::FileUnreadable,
            Self::Load(_) => ErrorCode::FormatMalformed,
            Self::Fs(_) | Self::BadMeta(_) | Self::Program(_) | Self::InsideGitTree(_) => {
                ErrorCode::InternalError
            }
        }
    }
}

impl fmt::Display for ProjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fs(e) => e.fmt(f),
            Self::Locked {
                owner: Some(o),
                stale,
            } => write!(
                f,
                "The process {o} holds the project lock{}.",
                if *stale { ", and it is not alive" } else { "" }
            ),
            Self::Locked { owner: None, .. } => f.write_str("The project lock does not parse."),
            Self::Corrupt { line } => write!(f, "The journal line {line} fails its checksum."),
            Self::BadMeta(e) => write!(f, "The project file is bad: {e}"),
            Self::BadInput => f.write_str("The input copy does not have the project SHA-256."),
            Self::Load(e) => write!(f, "The input copy does not load: {e}"),
            Self::Program(e) => write!(f, "The program does not build: {e}"),
            Self::ReadOnly => f.write_str("The project is open in read-only mode."),
            Self::Replay(e) => e.fmt(f),
            Self::InsideGitTree(p) => write!(
                f,
                "The projects root {} is inside a git working tree.",
                p.display()
            ),
        }
    }
}

impl std::error::Error for ProjectError {}

impl From<FsError> for ProjectError {
    fn from(e: FsError) -> Self {
        Self::Fs(e)
    }
}

/// One project directory.
pub struct Project {
    fs: Box<dyn Fs>,
    dir: PathBuf,
    meta: ProjectMeta,
    read_only: bool,
    owner: Option<LockInfo>,
    lines: u64,
    since_snapshot: u64,
    last_run: Option<RunLine>,
    engine: Value,
}

impl fmt::Debug for Project {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Project")
            .field("dir", &self.dir)
            .field("binary_id", &self.meta.binary_id)
            .field("read_only", &self.read_only)
            .field("lines", &self.lines)
            .finish_non_exhaustive()
    }
}

impl Project {
    /// Gives the project directory of the binary `id` under the projects root `root`.
    #[must_use]
    pub fn dir_of(root: &Path, id: BinaryId) -> PathBuf {
        root.join(id.to_string())
    }

    /// Tells if `dir` holds a project: its project file exists.
    pub fn exists(fs: &mut dyn Fs, dir: &Path) -> bool {
        fs.exists(&dir.join(PROJECT_FILE))
    }

    /// Makes the project of `program` under `root` and takes its lock.
    ///
    /// The steps are the directory, the lock, `.gitignore`, the input copy with mode 0444, an
    /// empty journal and the project file last. A directory without a project file is an
    /// incomplete project, so the steps replace its files.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Locked`] when a live process holds the lock, and
    /// [`ProjectError::Fs`] for a failed file operation.
    pub fn create(
        fs: Box<dyn Fs>,
        root: &Path,
        meta: ProjectMeta,
        bytes: &[u8],
        program: &Program,
        opts: &OpenOptions,
    ) -> Result<Self, ProjectError> {
        if sha256(bytes) != meta.sha256 || program.meta().sha256 != meta.sha256 {
            return Err(ProjectError::BadInput);
        }
        let mut fs = fs;
        let dir = Self::dir_of(root, meta.binary_id);
        if Self::exists(fs.as_mut(), &dir) {
            return Err(ProjectError::Fs(FsError::Exists(dir.join(PROJECT_FILE))));
        }
        fs.create_dir_all(&dir.join(BIN_DIR))?;
        // A directory without a project file holds no facts, so its lock can go.
        lock::acquire(fs.as_mut(), &dir, &opts.me, true).map_err(disk::lock_error)?;
        let mut project = Self {
            fs,
            dir,
            meta,
            read_only: false,
            owner: Some(opts.me.clone()),
            lines: 0,
            since_snapshot: 0,
            last_run: None,
            engine: opts.engine.clone(),
        };
        disk::write_new(&mut project, bytes)?;
        Ok(project)
    }

    /// Opens the project in `dir` (the open flow of design Section 3.10).
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Locked`] for a held lock and [`ProjectError::BadMeta`] for a bad
    /// project file. A changed input copy gives [`ProjectError::BadInput`]. A bad line in the
    /// middle of the journal gives [`ProjectError::Corrupt`], and a line that does not replay
    /// gives [`ProjectError::Replay`].
    pub fn open(fs: Box<dyn Fs>, dir: &Path, opts: &OpenOptions) -> Result<Opened, ProjectError> {
        let mut fs = fs;
        let bytes = fs.read(&dir.join(PROJECT_FILE))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| ProjectError::BadMeta("the project file is not UTF-8".to_owned()))?;
        let value = ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT)
            .map_err(|e| ProjectError::BadMeta(e.to_string()))?;
        let meta = ProjectMeta::from_json(&value)?;
        let owner = match opts.access {
            Access::Write { break_lock } => {
                lock::acquire(fs.as_mut(), dir, &opts.me, break_lock).map_err(disk::lock_error)?;
                Some(opts.me.clone())
            }
            Access::ReadOnly => None,
        };
        let mut project = Self {
            fs,
            dir: dir.to_path_buf(),
            meta,
            read_only: owner.is_none(),
            owner,
            lines: 0,
            since_snapshot: 0,
            last_run: None,
            engine: opts.engine.clone(),
        };
        let loaded = project.load(&opts.limits)?;
        Ok(Opened {
            project,
            program: loaded.program,
            history: loaded.history,
            tail_discarded: loaded.tail_discarded,
            analysis: loaded.analysis,
        })
    }

    /// Reads the state of the project again: the input copy, the snapshot and the journal. A
    /// write open keeps its lock. A torn last line of a write open goes out of the journal.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::BadInput`] for a changed input copy. A bad line in the middle of
    /// the journal gives [`ProjectError::Corrupt`], and a line that does not replay gives
    /// [`ProjectError::Replay`].
    pub fn load(&mut self, limits: &Limits) -> Result<Loaded, ProjectError> {
        disk::load(self, limits)
    }

    /// Gives the project directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Gives the project file.
    #[must_use]
    pub const fn meta(&self) -> &ProjectMeta {
        &self.meta
    }

    /// Tells if the project is open in read-only mode.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Gives the number of journal lines.
    #[must_use]
    pub const fn lines(&self) -> u64 {
        self.lines
    }

    /// Gives the last analysis run of the journal, or `None`.
    #[must_use]
    pub const fn last_run(&self) -> Option<&RunLine> {
        self.last_run.as_ref()
    }

    /// Sets the analyzer versions of the analysis inputs hash.
    pub fn set_engine(&mut self, engine: Value) {
        self.engine = engine;
    }

    /// Appends one line to the journal and syncs it. After every [`SNAPSHOT_EVERY`] lines,
    /// the call also writes a snapshot of `program`. Gives `true` when it wrote one.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::ReadOnly`] for a read-only project and [`ProjectError::Fs`]
    /// for a failed write or sync.
    pub fn append(&mut self, line: &Line, program: &Program) -> Result<bool, ProjectError> {
        if self.read_only {
            return Err(ProjectError::ReadOnly);
        }
        let mut text = crate::journal::encode(line);
        text.push('\n');
        let path = self.dir.join(JOURNAL_FILE);
        self.fs.append(&path, text.as_bytes())?;
        self.fs.sync_file(&path)?;
        self.lines = self.lines.saturating_add(1);
        self.since_snapshot = self.since_snapshot.saturating_add(1);
        if let Line::Run(run) = line {
            self.last_run = Some(*run);
        }
        if self.since_snapshot >= SNAPSHOT_EVERY {
            self.snapshot(program)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Writes a snapshot of `program` that covers all journal lines.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::ReadOnly`] for a read-only project and [`ProjectError::Fs`]
    /// for a failed operation.
    pub fn snapshot(&mut self, program: &Program) -> Result<(), ProjectError> {
        if self.read_only {
            return Err(ProjectError::ReadOnly);
        }
        let inputs = self.last_run.map(|run| run.inputs_hash);
        let text = snapshot::encode(program, self.lines, inputs)
            .map_err(|e| ProjectError::Program(e.to_string()))?;
        snapshot::write(self.fs.as_mut(), &self.dir, &text)?;
        self.since_snapshot = 0;
        Ok(())
    }

    /// Writes the crash record `crash/<id>.json`. Gives its path relative to the project.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::ReadOnly`] for a read-only project and [`ProjectError::Fs`]
    /// for a failed operation.
    pub fn write_crash(&mut self, id: &str, record: &Value) -> Result<String, ProjectError> {
        if self.read_only {
            return Err(ProjectError::ReadOnly);
        }
        if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ProjectError::BadMeta("the crash ID is not hex".to_owned()));
        }
        let dir = self.dir.join(CRASH_DIR);
        self.fs.create_dir_all(&dir)?;
        let name = format!("{id}.json");
        let mut text = ghidorah_json::write_pretty(record);
        text.push('\n');
        crate::fs::replace_file(
            self.fs.as_mut(),
            &dir.join(&name),
            &dir.join(format!("{id}.tmp")),
            text.as_bytes(),
        )?;
        self.fs.sync_dir(&dir)?;
        Ok(format!("{CRASH_DIR}/{name}"))
    }

    /// Removes the lock of this process. A second call does nothing.
    pub fn release(&mut self) {
        if let Some(me) = self.owner.take() {
            let _ = crate::lock::release(self.fs.as_mut(), &self.dir, &me);
        }
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        self.release();
    }
}
