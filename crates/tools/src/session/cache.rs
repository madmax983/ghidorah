//! The decompile cache of each open binary (design Sections 3.9 and 8.5, AC-104b).
//!
//! Each open binary has one [`Cache`] of [`DEFAULT_CAPACITY`] outputs. The key of an output
//! is [`ghidorah_decomp::cache::key`]: the function, its `func_epoch` and the options hash.
//! The cache also holds the identity of the program of its outputs. The identity changes when
//! the session builds the program again. Then the old outputs go, so a new program never
//! reads an old output:
//!
//! | Event | Effect |
//! |---|---|
//! | [`Session::open`] puts a binary | a new identity |
//! | the session reloads the binary after a handler panic | a new identity |
//! | the rev of the program is lower than the highest rev of the cache | a new identity |
//! | a decompile in an open batch | no read and no put |
//!
//! A batch rollback drops the revs of the batch, and a later commit can get the same rev.
//! So the cache keeps no output of a batch program.

use std::collections::BTreeMap;
use std::sync::Arc;

use ghidorah_base::{BinaryId, Fuel, FuncId, Rev};
use ghidorah_decomp::cache::{DEFAULT_CAPACITY, Stats};
use ghidorah_decomp::{Cache, Opts, Output};

use super::{OpenBinary, Session, Store};

/// The decompile cache of one open binary.
#[derive(Debug, Clone)]
struct Slot {
    /// The program identity: the number of the builds of the program that the session saw.
    identity: u64,
    /// The highest rev of a program that read the cache.
    top: Rev,
    /// The outputs of the current identity.
    cache: Cache,
    /// The lookup counts of the earlier identities.
    before: Stats,
}

impl Slot {
    /// Makes the empty slot of the first identity.
    fn new() -> Self {
        Self {
            identity: 0,
            top: Rev(0),
            cache: Cache::new(DEFAULT_CAPACITY),
            before: Stats::default(),
        }
    }

    /// Starts a new identity: the outputs of the old program go.
    fn renew(&mut self) {
        let old = std::mem::replace(&mut self.cache, Cache::new(DEFAULT_CAPACITY));
        self.before = add(self.before, old.stats());
        self.identity = self.identity.saturating_add(1);
        self.top = Rev(0);
    }

    /// Gives the lookup counts of every identity.
    fn stats(&self) -> Stats {
        add(self.before, self.cache.stats())
    }
}

/// Gives the sum of two lookup counts.
const fn add(a: Stats, b: Stats) -> Stats {
    Stats {
        hits: a.hits.saturating_add(b.hits),
        misses: a.misses.saturating_add(b.misses),
    }
}

/// The decompile caches of the open binaries.
#[derive(Debug, Clone, Default)]
pub(crate) struct DecompCaches {
    slots: BTreeMap<BinaryId, Slot>,
}

impl DecompCaches {
    /// Starts a new program identity for the binary `id`.
    pub(crate) fn renew(&mut self, id: BinaryId) {
        self.slots.entry(id).or_insert_with(Slot::new).renew();
    }
}

impl Session {
    /// Adds an open binary and makes it the most recent one. A binary with the same ID goes.
    /// A binary with no store gets a store in memory. The binary gets a new program
    /// identity, so its decompile cache starts empty.
    pub fn open(&mut self, binary: OpenBinary) {
        let id = binary.id;
        self.stores
            .entry(id)
            .or_insert_with(|| Store::in_memory(&binary.program));
        self.binaries.insert(id, binary);
        self.decomp.get_mut().renew(id);
        self.touch(id);
    }

    /// Gives the decompile of `func` in the open binary `id` with `opts`. The output comes
    /// from the decompile cache of the binary, or the call renders it and puts it there. A
    /// call in an open batch renders the output and puts nothing.
    ///
    /// # Errors
    ///
    /// Returns the text of the decompile error, or a text for a binary that is not open.
    pub fn decompile(
        &self,
        id: BinaryId,
        func: FuncId,
        opts: &Opts,
        fuel: &mut Fuel,
    ) -> Result<Arc<Output>, String> {
        let names = &ghidorah_x86::lift::Names;
        let program = &self
            .binaries
            .get(&id)
            .ok_or_else(|| format!("The binary {id} is not open."))?
            .program;
        if self.in_batch(id) {
            return ghidorah_decomp::render(program, func, opts, names, fuel)
                .map(Arc::new)
                .map_err(|e| e.to_string());
        }
        let mut caches = self.decomp.borrow_mut();
        caches.slots.retain(|k, _| self.binaries.contains_key(k));
        let slot = caches.slots.entry(id).or_insert_with(Slot::new);
        let rev = program.rev();
        if rev < slot.top {
            slot.renew();
        }
        slot.top = slot.top.max(rev);
        slot.cache
            .render(program, func, opts, names, fuel)
            .map(|(out, _)| out)
            .map_err(|e| e.to_string())
    }

    /// Gives the lookup counts of the decompile cache of the open binary `id` since its
    /// first open. Tests read the hit count.
    #[must_use]
    pub fn decomp_stats(&self, id: BinaryId) -> Stats {
        self.decomp
            .borrow()
            .slots
            .get(&id)
            .map(Slot::stats)
            .unwrap_or_default()
    }
}
