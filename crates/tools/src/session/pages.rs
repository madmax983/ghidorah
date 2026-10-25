//! The page store of the analysis work state in a project directory (ADR-0031 stage 3).
//!
//! Each page is one file `work/<index as 16 hex digits>.page`. The pages are a cache of the
//! engine of one process, so a write needs no sync and no temporary file. The engine reads
//! only the pages that it wrote. A new store removes the pages of an earlier process.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ghidorah_analysis::pages::{PageError, PageStore};
use ghidorah_base::BinaryId;
use ghidorah_db::Fs;
use ghidorah_db::project::WORK_DIR;

use super::Session;

#[cfg(test)]
mod tests;

/// The pages of one binary in its project directory.
pub struct ProjectPages {
    fs: Box<dyn Fs>,
    dir: PathBuf,
    /// `true` after the directory exists.
    made: bool,
    /// The pages with a file.
    files: BTreeSet<u64>,
}

impl std::fmt::Debug for ProjectPages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectPages")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl ProjectPages {
    /// Makes the store of the pages in `dir`.
    #[must_use]
    pub fn new(fs: Box<dyn Fs>, dir: PathBuf) -> Self {
        Self {
            fs,
            dir,
            made: false,
            files: BTreeSet::new(),
        }
    }

    fn path(&self, page: u64) -> PathBuf {
        self.dir.join(format!("{page:016x}.page"))
    }
}

/// Gives the page error of a file system error.
fn io(e: &ghidorah_db::FsError) -> PageError {
    PageError::Io(e.to_string())
}

impl PageStore for ProjectPages {
    fn read(&mut self, page: u64) -> Result<Option<Vec<u8>>, PageError> {
        match self.fs.read(&self.path(page)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(io(&e)),
        }
    }

    fn write(&mut self, page: u64, bytes: &[u8]) -> Result<(), PageError> {
        if !self.made {
            self.fs.create_dir_all(&self.dir).map_err(|e| io(&e))?;
            self.made = true;
        }
        let path = self.path(page);
        // A write replaces the content of a file that exists. A file of an earlier process
        // that a clear left is such a file.
        if !self.files.contains(&page) && !self.fs.exists(&path) {
            self.fs.create_new(&path).map_err(|e| io(&e))?;
        }
        self.files.insert(page);
        self.fs.write_all(&path, bytes).map_err(|e| io(&e))
    }

    fn clear(&mut self) -> Result<(), PageError> {
        let names = match self.fs.list(&self.dir) {
            Ok(names) => names,
            Err(e) if e.is_not_found() => return Ok(()),
            Err(e) => return Err(io(&e)),
        };
        self.files.clear();
        // The store makes each name, so the case of the extension does not change.
        let pages = names.iter().filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e == "page")
        });
        for name in pages {
            self.fs.remove(&self.dir.join(name)).map_err(|e| io(&e))?;
        }
        Ok(())
    }
}

impl Session {
    /// Gives the engine a page store for the binary `id` once. Only a project that takes
    /// writes gets a store. A binary in memory keeps all pages in memory.
    pub(super) fn give_pages(&mut self, id: BinaryId) {
        if self.paged.contains(&id) {
            return;
        }
        let Some(dir) = self
            .stores
            .get(&id)
            .and_then(|s| s.project.as_ref())
            .filter(|p| !p.is_read_only())
            .map(|p| p.dir().join(WORK_DIR))
        else {
            return;
        };
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        engine.set_pages(id, Box::new(ProjectPages::new(self.fs.boxed(), dir)));
        self.paged.insert(id);
    }
}
