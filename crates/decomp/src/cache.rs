//! The decompile cache (design Section 8.5, AC-104b).
//!
//! The key is `(FuncId, func_epoch, options hash)`. A rename, a retype, a comment or a
//! signature change of the function or of a callee changes `func_epoch` (design Section 3.8),
//! so the next lookup misses. The cache holds at most its capacity of outputs. A full cache
//! drops the entry with the oldest use. The use counter is a plain counter, so the order is
//! deterministic.

use std::collections::BTreeMap;
use std::sync::Arc;

use ghidorah_base::{Fnv1a64, Fuel, FuncId, Rev};
use ghidorah_db::Program;
use ghidorah_ir::IntrinsicNames;

use crate::{DecompError, Opts, Output};

/// The default capacity of a cache: 512 outputs (design Section 3.9).
pub const DEFAULT_CAPACITY: usize = 512;

/// The key of a cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    /// The function.
    pub func: FuncId,
    /// The epoch of the function.
    pub epoch: Rev,
    /// The hash of the decompile options.
    pub opts: u64,
}

/// Gives the FNV-1a 64 hash of the options.
#[must_use]
pub fn opts_hash(opts: &Opts) -> u64 {
    let mut h = Fnv1a64::new();
    h.write(
        &u64::try_from(opts.max_nodes)
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    let p = opts.passes;
    for flag in [p.fold, p.sailr, p.canary, p.tailcall] {
        h.write_u8(u8::from(flag));
    }
    h.finish()
}

/// Gives the key of a decompile of `func` in `program` with `opts`.
#[must_use]
pub fn key(program: &Program, func: FuncId, opts: &Opts) -> Key {
    Key {
        func,
        epoch: program.func_epoch(func),
        opts: opts_hash(opts),
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

/// A cache of decompile outputs.
#[derive(Debug, Clone, Default)]
pub struct Cache {
    capacity: usize,
    tick: u64,
    entries: BTreeMap<Key, (u64, Arc<Output>)>,
    stats: Stats,
}

impl Cache {
    /// Makes an empty cache with room for `capacity` outputs. A capacity of 0 counts as 1.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            tick: 0,
            entries: BTreeMap::new(),
            stats: Stats::default(),
        }
    }

    /// Gives the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Tells if the cache has no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gives the lookup counts.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }

    /// Gives the next use count.
    const fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.saturating_add(1);
        self.tick
    }

    /// Gives the output of `key` and counts a hit, or counts a miss.
    pub fn get(&mut self, key: &Key) -> Option<Arc<Output>> {
        let tick = self.next_tick();
        if let Some((used, out)) = self.entries.get_mut(key) {
            *used = tick;
            self.stats.hits = self.stats.hits.saturating_add(1);
            return Some(Arc::clone(out));
        }
        self.stats.misses = self.stats.misses.saturating_add(1);
        None
    }

    /// Puts the output of `key`. A full cache drops the entry with the oldest use first.
    pub fn put(&mut self, key: Key, output: Output) -> Arc<Output> {
        let tick = self.next_tick();
        if !self.entries.contains_key(&key) {
            while self.entries.len() >= self.capacity {
                let oldest = self
                    .entries
                    .iter()
                    .min_by_key(|(k, (used, _))| (*used, **k))
                    .map(|(k, _)| *k);
                match oldest {
                    Some(k) => {
                        let _ = self.entries.remove(&k);
                    }
                    None => break,
                }
            }
        }
        let out = Arc::new(output);
        self.entries.insert(key, (tick, Arc::clone(&out)));
        out
    }

    /// Gives the output of `func` from the cache, or renders and puts it. The flag tells if
    /// the lookup found the entry.
    ///
    /// # Errors
    ///
    /// Returns the [`DecompError`] of the render.
    pub fn render(
        &mut self,
        program: &Program,
        func: FuncId,
        opts: &Opts,
        names: &dyn IntrinsicNames,
        fuel: &mut Fuel,
    ) -> Result<(Arc<Output>, bool), DecompError> {
        let key = key(program, func, opts);
        if let Some(out) = self.get(&key) {
            return Ok((out, true));
        }
        let out = crate::render(program, func, opts, names, fuel)?;
        Ok((self.put(key, out), false))
    }
}
