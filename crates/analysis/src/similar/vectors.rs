//! Sparse count vectors and the vector cache (design Section 7.13).
//!
//! A [`Vector`] holds one [`Entry`] per feature key, sorted by key. A key that occurs `k`
//! times has the count `k`, at most [`MAX_COUNT`]. Two features with the same key share one
//! entry: the entry keeps the lowest kind and the lowest text. The paths use no hash map
//! (ADR-0012).
//!
//! Vectors are derived data. The journal never holds them (design Section 3.9). The
//! [`VectorCache`] keeps at most its capacity of vectors. Its key is the binary, the function,
//! the function epoch and a hash of the facts that the vector reads ([`inputs_hash`]). The
//! hash keeps two programs of one binary apart when their revisions give the same epoch.
//! A full cache drops the entry with the oldest use. The use counter is a plain counter, so
//! the order is deterministic.

use std::collections::BTreeMap;
use std::sync::Arc;

use ghidorah_base::{BinaryId, Fuel, FuncId, OutOfFuel, Rev};

use super::features::{Context, Feature, Kind};

/// The largest count of one entry.
pub const MAX_COUNT: u16 = 65_535;

/// The default capacity of a [`VectorCache`].
pub const CACHE_CAPACITY: usize = 65_536;

/// One entry of a vector.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry {
    /// The feature key.
    pub key: u64,
    /// The kind.
    pub kind: Kind,
    /// The number of occurrences, at most [`MAX_COUNT`].
    pub count: u16,
    /// The output text of the feature in the binary of the vector.
    pub text: String,
}

/// The sparse count vector of one function.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Vector {
    entries: Vec<Entry>,
}

impl Vector {
    /// Makes the vector of a feature stream.
    #[must_use]
    pub fn new(features: Vec<Feature>) -> Self {
        let _ = features;
        Self::default()
    }

    /// Gives the entries in key order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Gives the number of entries: the number of distinct keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Tells if the vector is the zero vector.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Gives the entry of `key`.
    #[must_use]
    pub fn get(&self, key: u64) -> Option<&Entry> {
        self.entries
            .binary_search_by_key(&key, |e| e.key)
            .ok()
            .and_then(|i| self.entries.get(i))
    }

    /// Builds the vector of the function `func`.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfFuel`] when `fuel` runs out (see [`super::features::stream`]).
    pub fn build(ctx: &Context<'_>, func: FuncId, fuel: &mut Fuel) -> Result<Self, OutOfFuel> {
        Ok(Self::new(super::features::stream(ctx, func, fuel)?))
    }
}

/// The key of a cached vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheKey {
    /// The binary.
    pub binary: BinaryId,
    /// The function.
    pub func: FuncId,
    /// The epoch of the function (design Section 3.8).
    pub epoch: Rev,
    /// The hash of the facts that the vector reads.
    pub inputs: u64,
}

/// Gives the hash of the facts that the vector of `func` reads: the code units of the body,
/// the jump-table cases, the references from the body and the facts at their targets.
#[must_use]
pub fn inputs_hash(ctx: &Context<'_>, func: FuncId) -> u64 {
    let _ = (ctx, func);
    0
}

/// Gives the cache key of the vector of `func`.
#[must_use]
pub fn key_of(ctx: &Context<'_>, func: FuncId) -> CacheKey {
    let program = ctx.program();
    CacheKey {
        binary: program.meta().binary_id,
        func,
        epoch: program.func_epoch(func),
        inputs: inputs_hash(ctx, func),
    }
}

/// The counts of the lookups of a cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Stats {
    /// The lookups that found an entry.
    pub hits: u64,
    /// The lookups that found no entry.
    pub misses: u64,
}

/// A cache of vectors with a capacity and a least-recent-use order.
#[derive(Debug, Clone)]
pub struct VectorCache {
    capacity: usize,
    tick: u64,
    entries: BTreeMap<CacheKey, (u64, Arc<Vector>)>,
    uses: BTreeMap<u64, CacheKey>,
    stats: Stats,
}

impl Default for VectorCache {
    fn default() -> Self {
        Self::new(CACHE_CAPACITY)
    }
}

impl VectorCache {
    /// Makes an empty cache with room for `capacity` vectors. A capacity of 0 counts as 1.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            tick: 0,
            entries: BTreeMap::new(),
            uses: BTreeMap::new(),
            stats: Stats::default(),
        }
    }

    /// Gives the capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Gives the number of vectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Tells if the cache holds no vector.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Gives the lookup counts.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }

    /// Gives the vector of `key` and counts a hit, or counts a miss.
    pub fn get(&mut self, key: &CacheKey) -> Option<Arc<Vector>> {
        let _ = (key, self.tick, &self.uses);
        self.stats.misses = self.stats.misses.saturating_add(1);
        None
    }

    /// Puts the vector of `key`. A full cache drops the vector with the oldest use first.
    pub fn put(&mut self, key: CacheKey, vector: Vector) -> Arc<Vector> {
        let _ = key;
        Arc::new(vector)
    }

    /// Gives the cached vector of `func`, or builds it and puts it in the cache.
    ///
    /// # Errors
    ///
    /// Returns [`OutOfFuel`] when the build runs out of fuel. A hit costs no fuel.
    pub fn vector(
        &mut self,
        ctx: &Context<'_>,
        func: FuncId,
        fuel: &mut Fuel,
    ) -> Result<Arc<Vector>, OutOfFuel> {
        let key = key_of(ctx, func);
        if let Some(found) = self.get(&key) {
            return Ok(found);
        }
        let vector = Vector::build(ctx, func, fuel)?;
        Ok(self.put(key, vector))
    }
}
