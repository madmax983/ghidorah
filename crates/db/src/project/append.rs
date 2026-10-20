//! The writes of an open project: journal lines, snapshots and crash records.
//!
//! [`Project::append`] keeps the journal length before each line. After a failed write or a
//! failed sync, it cuts the journal back to that length. So a partial line never stays in
//! front of the next line. When the cut also fails, the project stops: each later write gives
//! the first error and changes no file. A reload ([`Project::load`]) repairs the torn tail
//! and lets the project write again.

use std::path::Path;

use ghidorah_json::Value;

use super::{CRASH_DIR, Project, ProjectError, SNAPSHOT_EVERY};
use crate::fs::FsError;
use crate::journal::{JOURNAL_FILE, Line};
use crate::program::Program;
use crate::snapshot;

impl Project {
    /// Appends one line to the journal and syncs it. After every [`SNAPSHOT_EVERY`] lines,
    /// the call also writes a snapshot of `program`. Gives `true` when it wrote one.
    ///
    /// A failed write or sync cuts the journal back to its length before the call.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::ReadOnly`] for a read-only project and [`ProjectError::Fs`]
    /// for a failed write or sync. After a failed cut, each call gives the first error.
    pub fn append(&mut self, line: &Line, program: &Program) -> Result<bool, ProjectError> {
        self.writable()?;
        let mut text = crate::journal::encode(line);
        text.push('\n');
        let path = self.dir.join(JOURNAL_FILE);
        let written = self
            .fs
            .append(&path, text.as_bytes())
            .and_then(|()| self.fs.sync_file(&path));
        if let Err(e) = written {
            self.cut_back(&path, &e);
            return Err(e.into());
        }
        let added = u64::try_from(text.len()).unwrap_or(u64::MAX);
        self.journal_len = self.journal_len.saturating_add(added);
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

    /// Cuts the journal back to its length before a failed append. When the cut fails, the
    /// project keeps the error `e` and stops.
    fn cut_back(&mut self, path: &Path, e: &FsError) {
        if self.fs.truncate(path, self.journal_len).is_err() {
            self.failed = Some(e.clone());
        }
    }

    /// Checks that the project can write: it is not read-only, and no cut failed.
    fn writable(&self) -> Result<(), ProjectError> {
        if self.read_only {
            return Err(ProjectError::ReadOnly);
        }
        match &self.failed {
            Some(e) => Err(ProjectError::Fs(e.clone())),
            None => Ok(()),
        }
    }

    /// Writes a snapshot of `program` that covers all journal lines.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::ReadOnly`] for a read-only project and [`ProjectError::Fs`]
    /// for a failed operation. After a failed cut of the journal, it gives that first error.
    pub fn snapshot(&mut self, program: &Program) -> Result<(), ProjectError> {
        self.writable()?;
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
}
