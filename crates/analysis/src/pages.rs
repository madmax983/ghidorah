//! The page store of the work state (ADR-0031 stage 3).
//!
//! The work state keeps its code units and flow references in pages. Each page holds one
//! range of RAM offsets. With a [`PageStore`], the scheduler keeps a fixed number of pages
//! in memory and puts the other pages in the store. The crate stays pure: the caller gives
//! the store. `ghidorah-tools` gives a store in the project directory.
//!
//! The pages are a cache. The facts of an analysis do not depend on the store, on the page
//! size or on the number of loaded pages.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// The error of a page store operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageError {
    /// The store fails to read or write a page.
    Io(String),
    /// A page of the store is not in the page format.
    Corrupt {
        /// The index of the page.
        page: u64,
    },
    /// The store does not hold a page that it wrote.
    Missing {
        /// The index of the page.
        page: u64,
    },
}

impl fmt::Display for PageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "The page store fails: {e}"),
            Self::Corrupt { page } => write!(f, "Page {page} of the work state is corrupt"),
            Self::Missing { page } => write!(f, "The page store has no page {page}"),
        }
    }
}

impl std::error::Error for PageError {}

/// The storage of the pages that are not in memory.
///
/// A page has an index. The store keeps the last bytes of each index. The scheduler reads
/// only the indexes that it wrote.
pub trait PageStore: fmt::Debug + Send {
    /// Gives the bytes of page `page`, or `None` when the store has no such page.
    ///
    /// # Errors
    ///
    /// Returns [`PageError::Io`] when the read fails.
    fn read(&mut self, page: u64) -> Result<Option<Vec<u8>>, PageError>;

    /// Puts `bytes` as page `page` in place of the earlier bytes of the index.
    ///
    /// # Errors
    ///
    /// Returns [`PageError::Io`] when the write fails. Then the earlier bytes stay or the
    /// index has no bytes.
    fn write(&mut self, page: u64, bytes: &[u8]) -> Result<(), PageError>;

    /// Removes all pages.
    ///
    /// # Errors
    ///
    /// Returns [`PageError::Io`] when a remove fails.
    fn clear(&mut self) -> Result<(), PageError>;
}

/// The page limits of a scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLimits {
    /// The number of pages in memory. A load above the limit stores a random loaded page.
    pub loaded: usize,
    /// The size of a page as a power of two: a page holds `2^bits` RAM offsets.
    pub bits: u32,
}

impl PageLimits {
    /// The smallest page size: 256 offsets. A code unit is at most 15 bytes, so a unit
    /// covers at most two pages.
    pub const MIN_BITS: u32 = 8;

    /// The largest page size: 2^40 offsets.
    pub const MAX_BITS: u32 = 40;

    /// The page size with no store: 64 KiB.
    pub const DEFAULT_BITS: u32 = 16;
}

/// A page store in memory. Tests use it to make the scheduler load and store pages.
/// A clone shares the read and write counts, so a test can read the counts of a store that it gave away.
#[derive(Debug, Default, Clone)]
pub struct MemStore {
    pages: BTreeMap<u64, Vec<u8>>,
    writes: Arc<AtomicU64>,
    reads: Arc<AtomicU64>,
}

impl MemStore {
    /// Makes an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Gives the number of reads of a page that the store holds.
    #[must_use]
    pub fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    /// Gives the number of writes.
    #[must_use]
    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }
}

impl PageStore for MemStore {
    fn read(&mut self, page: u64) -> Result<Option<Vec<u8>>, PageError> {
        let bytes = self.pages.get(&page).cloned();
        if bytes.is_some() {
            self.reads.fetch_add(1, Ordering::Relaxed);
        }
        Ok(bytes)
    }

    fn write(&mut self, page: u64, bytes: &[u8]) -> Result<(), PageError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.pages.insert(page, bytes.to_vec());
        Ok(())
    }

    fn clear(&mut self) -> Result<(), PageError> {
        self.pages.clear();
        Ok(())
    }
}
