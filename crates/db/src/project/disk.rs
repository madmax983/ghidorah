//! The file steps of a project: the project file, the create steps, the load and the list.

use std::path::{Path, PathBuf};

use ghidorah_base::{BinaryId, Limits, Rev, hex, sha256};
use ghidorah_json::Value;

use super::{
    AnalysisStatus, BIN_DIR, GITIGNORE_FILE, GITIGNORE_TEXT, JOURNAL_TMP, LoadSpec, Loaded,
    PROJECT_FILE, PROJECT_TMP, Project, ProjectError, ProjectMeta, ProjectSummary,
};
use crate::codec::{CodecError, Obj};
use crate::fs::{Fs, FsError, replace_file};
use crate::history::History;
use crate::journal::{self, JOURNAL_FILE, JournalError, Line};
use crate::lock::LockError;
use crate::program::Program;
use crate::replay;
use crate::snapshot::{self, FORMAT_VERSION, SNAPSHOT_FILE, hash_from, inputs_hash};

/// The member names of the project file.
const META_MEMBERS: [&str; 7] = [
    "format_version",
    "binary_id",
    "sha256",
    "file_name",
    "load",
    "analysis_config",
    "ghidorah_version",
];

/// The longest file name of a project file in bytes.
const MAX_FILE_NAME: usize = 4_096;

/// Gives the project error of a lock error.
pub(super) fn lock_error(e: LockError) -> ProjectError {
    match e {
        LockError::Held(owner) => ProjectError::Locked {
            owner: Some(owner),
            stale: false,
        },
        LockError::Stale(owner) => ProjectError::Locked { owner, stale: true },
        LockError::Fs(e) => ProjectError::Fs(e),
    }
}

/// Gives the `BadMeta` error of a codec error.
fn bad(e: &CodecError) -> ProjectError {
    ProjectError::BadMeta(e.to_string())
}

/// Reads an optional 0x hex address of the load member.
fn hex_addr(v: &Value) -> Result<Option<u64>, CodecError> {
    if v.is_null() {
        return Ok(None);
    }
    v.as_str()
        .and_then(hex::parse_u64)
        .map(Some)
        .ok_or_else(|| CodecError::text("0x hex address"))
}

/// Reads the load member of a project file.
fn read_load(v: &Value) -> Result<LoadSpec, CodecError> {
    match v.get("format").and_then(Value::as_str) {
        Some("auto") => {
            Obj::new(v, &["format"])?;
            Ok(LoadSpec::Auto)
        }
        Some("raw") => {
            let o = Obj::new(v, &["format", "base", "entry"])?;
            let base = o
                .with("base", hex_addr)?
                .ok_or_else(|| CodecError::text("0x hex address").at("base"))?;
            Ok(LoadSpec::Raw {
                base,
                entry: o.with("entry", hex_addr)?,
            })
        }
        _ => Err(CodecError::text("load format").at("format")),
    }
}

/// Reads a project file.
pub(super) fn meta_from_json(value: &Value) -> Result<ProjectMeta, ProjectError> {
    let o = Obj::new(value, &META_MEMBERS).map_err(|e| bad(&e))?;
    let format_version: u64 = o.get("format_version").map_err(|e| bad(&e))?;
    if format_version != FORMAT_VERSION {
        return Err(ProjectError::BadMeta(format!(
            "the format version is {format_version}, not {FORMAT_VERSION}"
        )));
    }
    let sha256 = o.with("sha256", hash_from).map_err(|e| bad(&e))?;
    let id: String = o.get("binary_id").map_err(|e| bad(&e))?;
    let binary_id = BinaryId::parse(&id)
        .ok()
        .filter(|b| *b == BinaryId::from_sha256(&sha256))
        .ok_or_else(|| ProjectError::BadMeta("the binary ID is not the hash start".to_owned()))?;
    let file_name: String = o.get("file_name").map_err(|e| bad(&e))?;
    if file_name.is_empty() || file_name.len() > MAX_FILE_NAME {
        return Err(ProjectError::BadMeta(
            "the file name is empty or long".to_owned(),
        ));
    }
    Ok(ProjectMeta {
        format_version,
        binary_id,
        sha256,
        file_name,
        load: o.with("load", read_load).map_err(|e| bad(&e))?,
        analysis_config: o.member("analysis_config").map_err(|e| bad(&e))?.clone(),
        ghidorah_version: o.get("ghidorah_version").map_err(|e| bad(&e))?,
    })
}

/// Gives a temporary path next to `path`.
fn tmp_of(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Gives the path of the input copy of a project.
pub(super) fn bin_path(dir: &Path, meta: &ProjectMeta) -> PathBuf {
    dir.join(BIN_DIR).join(hex::encode(&meta.sha256))
}

/// Writes the files of a new project: `.gitignore`, the input copy, the journal and the
/// project file last. The caller holds the lock.
pub(super) fn write_new(project: &mut Project, bytes: &[u8]) -> Result<(), ProjectError> {
    let dir = project.dir.clone();
    let fs = project.fs.as_mut();
    let ignore = dir.join(GITIGNORE_FILE);
    replace_file(fs, &ignore, &tmp_of(&ignore), GITIGNORE_TEXT.as_bytes())?;
    let bin = bin_path(&dir, &project.meta);
    replace_file(fs, &bin, &tmp_of(&bin), bytes)?;
    fs.set_read_only(&bin)?;
    fs.sync_dir(&dir.join(BIN_DIR))?;
    let journal = dir.join(JOURNAL_FILE);
    if !fs.exists(&journal) {
        fs.create_new(&journal)?;
        fs.sync_file(&journal)?;
    }
    let mut text = ghidorah_json::write_pretty(&project.meta.to_json());
    text.push('\n');
    replace_file(
        fs,
        &dir.join(PROJECT_FILE),
        &dir.join(PROJECT_TMP),
        text.as_bytes(),
    )?;
    fs.sync_dir(&dir)?;
    if let Some(root) = dir.parent() {
        fs.sync_dir(root)?;
    }
    Ok(())
}

/// Reads a file, or gives an empty file for a path that does not exist.
fn read_or_empty(fs: &mut dyn Fs, path: &Path) -> Result<Vec<u8>, FsError> {
    match fs.read(path) {
        Ok(bytes) => Ok(bytes),
        Err(FsError::NotFound(_)) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Gives the revision of the last commit or run line of `lines`, or 0.
fn last_rev(lines: &[Line]) -> Rev {
    lines.iter().rev().find_map(Line::rev).unwrap_or(Rev(0))
}

/// Puts the snapshot of the project into `program` when it is valid and agrees with the
/// journal. Gives the number of journal lines that the snapshot covers, or 0.
fn restore_snapshot(fs: &mut dyn Fs, dir: &Path, lines: &[Line], program: &mut Program) -> usize {
    let Ok(bytes) = fs.read(&dir.join(SNAPSHOT_FILE)) else {
        return 0;
    };
    let Ok(snap) = snapshot::decode(&bytes) else {
        return 0;
    };
    let Some(covered) = usize::try_from(snap.journal_lines)
        .ok()
        .filter(|n| *n <= lines.len())
    else {
        return 0;
    };
    let agrees = lines
        .get(..covered)
        .is_some_and(|head| last_rev(head) == snap.rev);
    if agrees && snap.restore(program).is_ok() {
        covered
    } else {
        0
    }
}

/// Loads the program and the history of a project: the input copy, the snapshot, the replay
/// and the repair of a torn tail.
pub(super) fn load(project: &mut Project, limits: &Limits) -> Result<Loaded, ProjectError> {
    let dir = project.dir.clone();
    let fs = project.fs.as_mut();
    let bytes = fs.read(&bin_path(&dir, &project.meta))?;
    if sha256(&bytes) != project.meta.sha256 {
        return Err(ProjectError::BadInput);
    }
    let (binary, mem) = ghidorah_loader::load(&bytes, &project.meta.load.opts(), limits)
        .map_err(|e| ProjectError::Load(e.to_string()))?;
    let mut program = Program::from_binary(binary, mem, limits)
        .map_err(|e| ProjectError::Program(e.to_string()))?;
    let journal_path = dir.join(JOURNAL_FILE);
    let text = read_or_empty(fs, &journal_path)?;
    let journal = journal::parse(&text).map_err(|e| match e {
        JournalError::Corrupt { line, .. } => ProjectError::Corrupt { line },
    })?;
    let skip = restore_snapshot(fs, &dir, &journal.lines, &mut program);
    let mut history = History::new();
    let replayed = replay::replay(&mut program, &journal.lines, skip, &mut history)
        .map_err(ProjectError::Replay)?;
    if journal.torn && !project.read_only {
        let valid = text.get(..journal.valid_len).unwrap_or_default();
        replace_file(fs, &journal_path, &dir.join(JOURNAL_TMP), valid)?;
        fs.sync_dir(&dir)?;
    }
    let lines = u64::try_from(journal.lines.len()).unwrap_or(u64::MAX);
    let covered = u64::try_from(skip).unwrap_or(u64::MAX);
    project.lines = lines;
    project.since_snapshot = lines.saturating_sub(covered);
    project.last_run = replayed.last_run;
    let current = replayed.last_run.is_some_and(|run| {
        !replayed.behind
            && run.inputs_hash
                == inputs_hash(&program, &project.engine, &project.meta.analysis_config)
    });
    Ok(Loaded {
        program,
        history,
        tail_discarded: journal.torn,
        analysis: AnalysisStatus {
            last_run: replayed.last_run,
            behind: replayed.behind,
            current,
        },
    })
}

/// Gives the summary of the project in `dir`, or `None` for a directory that is not a project.
fn summary(fs: &mut dyn Fs, dir: &Path) -> Option<ProjectSummary> {
    let bytes = fs.read(&dir.join(PROJECT_FILE)).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let value = ghidorah_json::parse(text, &ghidorah_json::Limits::DEFAULT).ok()?;
    let meta = meta_from_json(&value).ok()?;
    let journal = read_or_empty(fs, &dir.join(JOURNAL_FILE)).ok()?;
    let lines = journal::parse(&journal)
        .map(|j| j.lines)
        .unwrap_or_default();
    let last_session = lines.iter().rev().find_map(|l| match l {
        Line::Tx(t) => Some(t.session.as_str().to_owned()),
        _ => None,
    });
    Some(ProjectSummary {
        binary_id: meta.binary_id,
        file_name: meta.file_name,
        rev: last_rev(&lines),
        last_session,
    })
}

/// Gives the projects under `root`, newest revision first, then binary ID order.
pub(super) fn list(fs: &mut dyn Fs, root: &Path) -> Vec<ProjectSummary> {
    let names = fs.list(root).unwrap_or_default();
    let mut out: Vec<ProjectSummary> = names
        .iter()
        .filter(|name| BinaryId::parse(name).is_ok())
        .filter_map(|name| summary(fs, &root.join(name)))
        .collect();
    out.sort_by(|a, b| b.rev.cmp(&a.rev).then(a.binary_id.cmp(&b.binary_id)));
    out
}
