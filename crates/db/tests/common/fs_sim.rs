//! A simulated file system for the persistence tests (design Section 3.10).
//!
//! [`SimFs`] keeps files in memory. It has two views:
//!
//! - The live view: what the running process sees after each operation.
//! - The durable view: what a crash keeps. A file keeps the data of its last `sync_file`. A
//!   directory keeps the names of its last `sync_dir`. A new directory is durable at once.
//!
//! The log records each changing operation, for example `rename snapshot.json.tmp.7.0 snapshot.json`.
//! [`SimFs::stop_after`] lets `k` more changing operations work. Each later operation fails
//! with [`FsError::Stopped`]: the simulated crash. [`SimFs::crash_image`] gives a new file
//! system with the durable view only.
//!
//! All handles of [`Fs::boxed`] share one state.

#![allow(dead_code, reason = "each test uses a part of the helpers")]
#![allow(clippy::expect_used, reason = "a poisoned test lock fails the test")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use ghidorah_db::fs::{Fs, FsError};

/// One file.
#[derive(Debug, Clone, Default)]
struct Node {
    data: Vec<u8>,
    durable: Vec<u8>,
    read_only: bool,
}

/// The shared state.
#[derive(Debug, Default)]
struct State {
    nodes: Vec<Node>,
    names: BTreeMap<PathBuf, usize>,
    durable_names: BTreeMap<PathBuf, usize>,
    dirs: BTreeSet<PathBuf>,
    log: Vec<String>,
    budget: Option<usize>,
}

impl State {
    /// Counts one changing operation. Gives `Stopped` after the budget.
    fn step(&mut self, entry: String) -> Result<(), FsError> {
        match &mut self.budget {
            Some(0) => return Err(FsError::Stopped),
            Some(n) => *n -= 1,
            None => {}
        }
        self.log.push(entry);
        Ok(())
    }

    fn node(&mut self, path: &Path) -> Result<&mut Node, FsError> {
        let id = *self
            .names
            .get(path)
            .ok_or_else(|| FsError::NotFound(path.to_path_buf()))?;
        self.nodes
            .get_mut(id)
            .ok_or_else(|| FsError::NotFound(path.to_path_buf()))
    }

    fn parent_ok(&self, path: &Path) -> Result<(), FsError> {
        match path.parent() {
            Some(p) if !p.as_os_str().is_empty() && !self.dirs.contains(p) => {
                Err(FsError::NotFound(p.to_path_buf()))
            }
            _ => Ok(()),
        }
    }
}

/// A simulated file system with an operation log and a crash point.
#[derive(Debug, Clone, Default)]
pub struct SimFs(Arc<Mutex<State>>);

/// Gives the last part of a path, for the log.
fn short(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

impl SimFs {
    /// Makes an empty file system.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().expect("the test file system lock")
    }

    /// Puts a durable file with `bytes` and makes its parents. It does not count or log.
    pub fn seed(&self, path: &Path, bytes: &[u8]) {
        let mut s = self.state();
        for dir in path.ancestors().skip(1) {
            if !dir.as_os_str().is_empty() {
                s.dirs.insert(dir.to_path_buf());
            }
        }
        let id = s.nodes.len();
        s.nodes.push(Node {
            data: bytes.to_vec(),
            durable: bytes.to_vec(),
            read_only: false,
        });
        s.names.insert(path.to_path_buf(), id);
        s.durable_names.insert(path.to_path_buf(), id);
    }

    /// Gives the live bytes of a file, or `None`.
    #[must_use]
    pub fn get(&self, path: &Path) -> Option<Vec<u8>> {
        let s = self.state();
        s.names
            .get(path)
            .and_then(|id| s.nodes.get(*id))
            .map(|n| n.data.clone())
    }

    /// Tells if a file has the mode 0444.
    #[must_use]
    pub fn is_read_only(&self, path: &Path) -> bool {
        let s = self.state();
        s.names
            .get(path)
            .and_then(|id| s.nodes.get(*id))
            .is_some_and(|n| n.read_only)
    }

    /// Gives the log and clears it.
    #[must_use]
    pub fn take_log(&self) -> Vec<String> {
        std::mem::take(&mut self.state().log)
    }

    /// Lets `k` more changing operations work. Each later one fails with `Stopped`.
    pub fn stop_after(&self, k: usize) {
        self.state().budget = Some(k);
    }

    /// Removes the crash point.
    pub fn resume(&self) {
        self.state().budget = None;
    }

    /// Gives the number of logged operations.
    #[must_use]
    pub fn ops(&self) -> usize {
        self.state().log.len()
    }

    /// Gives a new file system with the durable view of this one.
    #[must_use]
    pub fn crash_image(&self) -> Self {
        let s = self.state();
        let mut out = State {
            dirs: s.dirs.clone(),
            ..State::default()
        };
        for (path, id) in &s.durable_names {
            if let Some(node) = s.nodes.get(*id) {
                let new = out.nodes.len();
                out.nodes.push(Node {
                    data: node.durable.clone(),
                    durable: node.durable.clone(),
                    read_only: node.read_only,
                });
                out.names.insert(path.clone(), new);
                out.durable_names.insert(path.clone(), new);
            }
        }
        Self(Arc::new(Mutex::new(out)))
    }
}

impl Fs for SimFs {
    fn create_dir_all(&mut self, path: &Path) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("create_dir_all {}", short(path)))?;
        for dir in path.ancestors() {
            if !dir.as_os_str().is_empty() {
                s.dirs.insert(dir.to_path_buf());
            }
        }
        Ok(())
    }

    fn create_new(&mut self, path: &Path) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("create_new {}", short(path)))?;
        if s.names.contains_key(path) || s.dirs.contains(path) {
            return Err(FsError::Exists(path.to_path_buf()));
        }
        s.parent_ok(path)?;
        let id = s.nodes.len();
        s.nodes.push(Node::default());
        s.names.insert(path.to_path_buf(), id);
        Ok(())
    }

    fn append(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("append {}", short(path)))?;
        s.node(path)?.data.extend_from_slice(bytes);
        Ok(())
    }

    fn write_all(&mut self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("write_all {}", short(path)))?;
        s.node(path)?.data = bytes.to_vec();
        Ok(())
    }

    fn sync_file(&mut self, path: &Path) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("sync_file {}", short(path)))?;
        let node = s.node(path)?;
        node.durable = node.data.clone();
        Ok(())
    }

    fn rename(&mut self, from: &Path, to: &Path) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("rename {} {}", short(from), short(to)))?;
        let id = s
            .names
            .remove(from)
            .ok_or_else(|| FsError::NotFound(from.to_path_buf()))?;
        s.names.insert(to.to_path_buf(), id);
        Ok(())
    }

    fn link_new(&mut self, src: &Path, dst: &Path) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("link_new {} {}", short(src), short(dst)))?;
        if s.names.contains_key(dst) || s.dirs.contains(dst) {
            return Err(FsError::Exists(dst.to_path_buf()));
        }
        s.parent_ok(dst)?;
        let id = *s
            .names
            .get(src)
            .ok_or_else(|| FsError::NotFound(src.to_path_buf()))?;
        s.names.insert(dst.to_path_buf(), id);
        Ok(())
    }

    fn sync_dir(&mut self, path: &Path) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("sync_dir {}", short(path)))?;
        if !s.dirs.contains(path) {
            return Err(FsError::NotFound(path.to_path_buf()));
        }
        let in_dir = |p: &PathBuf| p.parent() == Some(path);
        s.durable_names.retain(|p, _| !in_dir(p));
        let live: Vec<(PathBuf, usize)> = s
            .names
            .iter()
            .filter(|(p, _)| in_dir(p))
            .map(|(p, id)| (p.clone(), *id))
            .collect();
        s.durable_names.extend(live);
        Ok(())
    }

    fn remove(&mut self, path: &Path) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("remove {}", short(path)))?;
        s.names
            .remove(path)
            .map(drop)
            .ok_or_else(|| FsError::NotFound(path.to_path_buf()))
    }

    fn read(&mut self, path: &Path) -> Result<Vec<u8>, FsError> {
        let mut s = self.state();
        if s.budget == Some(0) {
            return Err(FsError::Stopped);
        }
        s.node(path).map(|n| n.data.clone())
    }

    fn set_read_only(&mut self, path: &Path) -> Result<(), FsError> {
        let mut s = self.state();
        s.step(format!("set_read_only {}", short(path)))?;
        s.node(path)?.read_only = true;
        Ok(())
    }

    fn list(&mut self, dir: &Path) -> Result<Vec<String>, FsError> {
        let s = self.state();
        if !s.dirs.contains(dir) {
            return Err(FsError::NotFound(dir.to_path_buf()));
        }
        let mut names: BTreeSet<String> = s
            .names
            .keys()
            .chain(s.dirs.iter())
            .filter(|p| p.parent() == Some(dir))
            .map(|p| short(p))
            .collect();
        names.remove("");
        Ok(names.into_iter().collect())
    }

    fn exists(&mut self, path: &Path) -> bool {
        let s = self.state();
        s.names.contains_key(path) || s.dirs.contains(path)
    }

    fn boxed(&self) -> Box<dyn Fs> {
        Box::new(self.clone())
    }
}
