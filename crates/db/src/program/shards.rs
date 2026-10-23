//! The analysis set in shards of RAM offsets (ADR-0031).
//!
//! A shard holds the analysis facts of 4 MiB of RAM offsets in its own [`Tables`]. The key of
//! a fact gives its shard:
//!
//! | Fact | Address |
//! |---|---|
//! | code unit, data definition, string | its offset |
//! | symbol, comment, flow override, jump table | its address |
//! | function, signature, noreturn flag, variable | the entry of the function |
//! | reference | its `from` address |
//!
//! The facts at an address outside RAM go in the shard [`ShardId::OUTSIDE`]. The set keeps
//! each shard behind an [`Arc`], so a new set shares each shard that does not change. A set
//! never keeps an empty shard, so two sets with the same facts are equal.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::sync::{Arc, OnceLock};

use ghidorah_base::{Address, JumpTableId, Range};

use super::Tables;
use crate::comments::CommentKind;
use crate::fact::Fact;
use crate::funcs::Function;
use crate::jumptables::JumpTable;
use crate::listing::{CodeUnit, DataDef};
use crate::refs::{Ref, RefKey};
use crate::strings::StrInfo;
use crate::symbols::{SymKey, Symbol};
use crate::why::{FactKey, Why};

/// The number of offset bits in one shard: 2^22 bytes, 4 MiB.
pub const SHARD_BITS: u32 = 22;

/// The ID of a shard: the RAM offset shifted right by [`SHARD_BITS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardId(u64);

impl ShardId {
    /// The shard of the facts at an address outside RAM. It comes after each RAM shard.
    pub const OUTSIDE: Self = Self(u64::MAX);

    /// Gives the shard of the RAM offset `off`.
    #[must_use]
    pub const fn of_off(off: u64) -> Self {
        Self(off >> SHARD_BITS)
    }

    /// Gives the shard of `addr`.
    #[must_use]
    pub fn of(addr: Address) -> Self {
        if addr.is_ram() {
            Self::of_off(addr.off)
        } else {
            Self::OUTSIDE
        }
    }

    /// Gives the shard of the fact of `key`. An input of the binary with no address in RAM
    /// goes in [`Self::OUTSIDE`].
    #[must_use]
    pub fn of_key(key: &FactKey) -> Self {
        match key {
            FactKey::CodeUnit(off)
            | FactKey::Data(off)
            | FactKey::Entry(off)
            | FactKey::Reloc(off)
            | FactKey::Fde(off) => Self::of_off(*off),
            FactKey::Symbol(a, _) | FactKey::Comment(a, _) | FactKey::FlowOverride(a) => {
                Self::of(*a)
            }
            FactKey::Func(f) | FactKey::Signature(f) | FactKey::Noreturn(f) => Self::of(f.0),
            FactKey::Ref(k) => Self::of(k.from),
            FactKey::JumpTable(j) => Self::of(j.0),
            FactKey::Str(s) => Self::of(s.0),
            FactKey::Var(v) => Self::of(v.func.0),
            FactKey::Import(_) | FactKey::Export(_) | FactKey::Note(_) => Self::OUTSIDE,
        }
    }

    /// Gives the shard with the index `index`, as [`Self::index`] gives it.
    #[must_use]
    pub const fn from_index(index: u64) -> Self {
        Self(index)
    }

    /// Gives the index of the shard. [`Self::OUTSIDE`] has the index `u64::MAX`.
    #[must_use]
    pub const fn index(self) -> u64 {
        self.0
    }

    /// Gives the RAM offsets of the shard, or `None` for [`Self::OUTSIDE`].
    #[must_use]
    pub fn range(self) -> Option<Range> {
        if self == Self::OUTSIDE {
            return None;
        }
        let first = self.0.checked_shl(SHARD_BITS)?;
        Range::new(first, first | ((1u64 << SHARD_BITS) - 1))
    }
}

/// One shard: its tables and the SHA-256 of their JCS text. The hash comes on the first
/// request, and a change of the tables removes it.
#[derive(Debug, Default)]
pub(crate) struct Shard {
    /// The tables.
    tables: Tables,
    /// The SHA-256 of the JCS text of the tables.
    hash: OnceLock<[u8; 32]>,
}

impl Shard {
    /// Makes a shard of `tables`.
    pub(crate) fn new(tables: Tables) -> Self {
        Self {
            tables,
            hash: OnceLock::new(),
        }
    }

    /// Gives the SHA-256 of the JCS text of the tables.
    pub(crate) fn hash(&self) -> [u8; 32] {
        *self.hash.get_or_init(|| {
            let mut hasher = ghidorah_base::Sha256::default();
            let streamed = crate::codec::tables_jcs_to(&self.tables, &mut |p| {
                hasher.update(p.as_bytes());
            });
            if streamed.is_ok() {
                return hasher.finalize();
            }
            let text = ghidorah_json::write(&crate::codec::tables_to_json(&self.tables));
            ghidorah_base::sha256(text.as_bytes())
        })
    }

    /// Sets the SHA-256 that a reader checked. A shard with a hash keeps its hash.
    pub(crate) fn set_hash(&self, hash: [u8; 32]) {
        let _ = self.hash.set(hash);
    }
}

impl Clone for Shard {
    /// Copies the tables. The copy has no hash, because a change follows each copy.
    fn clone(&self) -> Self {
        Self::new(self.tables.clone())
    }
}

impl PartialEq for Shard {
    fn eq(&self, other: &Self) -> bool {
        self.tables == other.tables
    }
}

impl Eq for Shard {}

impl Deref for Shard {
    type Target = Tables;

    fn deref(&self) -> &Tables {
        &self.tables
    }
}

/// The analysis layer: every `Analysis` fact of a program, in shards.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalysisSet {
    /// The shards with one or more facts, in address order.
    shards: BTreeMap<ShardId, Arc<Shard>>,
    /// The shards with a function body outside the shard.
    wide: BTreeSet<ShardId>,
}

impl AnalysisSet {
    /// Makes an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Tells if the set has no fact.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    /// Gives the shards with one or more facts, in address order.
    #[must_use]
    pub fn shards(&self) -> impl DoubleEndedIterator<Item = (ShardId, &Tables)> {
        self.shards.iter().map(|(id, s)| (*id, &s.tables))
    }

    /// Gives the shard `id`, or `None` when it has no fact.
    #[must_use]
    pub fn shard(&self, id: ShardId) -> Option<&Tables> {
        self.shards.get(&id).map(|s| &s.tables)
    }

    /// Gives the shared shard `id`.
    pub(crate) fn shard_arc(&self, id: ShardId) -> Option<&Arc<Shard>> {
        self.shards.get(&id)
    }

    /// Gives the SHA-256 of the JCS text of the shard `id`. A shard keeps its hash, so a
    /// second request costs no encode.
    #[must_use]
    pub fn shard_hash(&self, id: ShardId) -> Option<[u8; 32]> {
        self.shards.get(&id).map(|s| s.hash())
    }

    /// Gives the shard of `addr`.
    #[must_use]
    pub fn at(&self, addr: Address) -> Option<&Tables> {
        self.shard(ShardId::of(addr))
    }

    /// Gives the shard of the RAM offset `off`.
    #[must_use]
    pub fn at_off(&self, off: u64) -> Option<&Tables> {
        self.shard(ShardId::of_off(off))
    }

    /// Gives the shard of the fact of `key`.
    #[must_use]
    pub fn of_key(&self, key: &FactKey) -> Option<&Tables> {
        self.shard(ShardId::of_key(key))
    }

    /// Puts `tables` as the shard `id`. An empty shard goes out of the set.
    pub(crate) fn put(&mut self, id: ShardId, tables: Tables) {
        self.keep(id, Arc::new(Shard::new(tables)));
    }

    /// Puts the shared shard `shard` as the shard `id`. An empty shard goes out of the set.
    pub(crate) fn keep(&mut self, id: ShardId, tables: Arc<Shard>) {
        if tables.tables == Tables::default() {
            self.shards.remove(&id);
            self.wide.remove(&id);
            return;
        }
        if is_wide(id, &tables) {
            self.wide.insert(id);
        } else {
            self.wide.remove(&id);
        }
        self.shards.insert(id, tables);
    }

    /// Moves the shard `id` of `part` into the set with the SHA-256 `hash` that a reader
    /// checked.
    pub(crate) fn absorb(&mut self, mut part: Self, id: ShardId, hash: [u8; 32]) {
        if let Some(shard) = part.shards.remove(&id) {
            shard.set_hash(hash);
            self.keep(id, shard);
        }
    }

    /// Gives the shard `id` for a change. A new shard starts empty. Call [`Self::tidy`]
    /// after the change.
    pub(crate) fn tables_mut(&mut self, id: ShardId) -> &mut Tables {
        let shard = Arc::make_mut(self.shards.entry(id).or_default());
        let _ = shard.hash.take();
        &mut shard.tables
    }

    /// Removes the empty shards and finds the wide shards again after [`Self::tables_mut`].
    pub(crate) fn tidy(&mut self) {
        let empty = Tables::default();
        self.shards.retain(|_, s| s.tables != empty);
        self.wide = self
            .shards
            .iter()
            .filter(|(id, t)| is_wide(**id, t))
            .map(|(id, _)| *id)
            .collect();
    }

    /// Gives the number of code units.
    #[must_use]
    pub fn unit_count(&self) -> usize {
        self.shards
            .values()
            .map(|t| t.listing.unit_count())
            .fold(0, usize::saturating_add)
    }

    /// Gives the code unit that starts at `off`.
    #[must_use]
    pub fn unit(&self, off: u64) -> Option<&CodeUnit> {
        self.at_off(off)?.listing.unit(off)
    }

    /// Gives the code unit whose bytes hold `off`, with its start. A unit of the shard
    /// before can reach into the shard of `off`.
    #[must_use]
    pub fn unit_containing(&self, off: u64) -> Option<(u64, &CodeUnit)> {
        let home = ShardId::of_off(off);
        let before = self.shards.range(..home).next_back();
        self.shard(home)
            .and_then(|t| t.listing.unit_containing(off))
            .or_else(|| before.and_then(|(_, t)| t.listing.unit_containing(off)))
    }

    /// Gives the code units that start in `range`, in address order.
    pub fn units_in(&self, range: Range) -> impl Iterator<Item = (u64, &CodeUnit)> {
        let lo = ShardId::of_off(range.first);
        let hi = ShardId::of_off(range.last.max(range.first));
        self.shards
            .range(lo..=hi)
            .flat_map(move |(_, t)| t.listing.units_in(range))
    }

    /// Gives all references, each shard in key order, the shards in address order.
    pub fn refs(&self) -> impl Iterator<Item = &Fact<Ref>> {
        self.shards.values().flat_map(|t| t.refs.iter())
    }

    /// Gives the data definition that starts at `off`.
    #[must_use]
    pub fn data(&self, off: u64) -> Option<&Fact<DataDef>> {
        self.at_off(off)?.listing.data(off)
    }

    /// Gives the data definition whose bytes hold `off`, with its start. A definition of any
    /// shard before can reach into the shard of `off`.
    #[must_use]
    pub fn data_containing(&self, off: u64) -> Option<(u64, &Fact<DataDef>)> {
        let home = ShardId::of_off(off);
        self.shards
            .range(..=home)
            .rev()
            .find_map(|(_, t)| t.listing.data_containing(off))
    }

    /// Gives a function.
    #[must_use]
    pub fn func(&self, id: ghidorah_base::FuncId) -> Option<&Function> {
        self.at(id.0)?.funcs.get(id)
    }

    /// Gives all functions in entry order.
    pub fn funcs(&self) -> impl Iterator<Item = &Function> {
        self.shards.values().flat_map(|t| t.funcs.iter())
    }

    /// Gives the function that owns the RAM offset `off`. The shard of `off` comes first, then
    /// each shard with a body outside the shard, in address order.
    #[must_use]
    pub fn owner_of(&self, off: u64) -> Option<ghidorah_base::FuncId> {
        let home = ShardId::of_off(off);
        self.shard(home)
            .and_then(|t| t.funcs.owner_of(off))
            .or_else(|| {
                self.wide
                    .iter()
                    .filter(|id| **id != home)
                    .find_map(|id| self.shard(*id)?.funcs.owner_of(off))
            })
    }

    /// Gives all strings in address order.
    pub fn strings(&self) -> impl Iterator<Item = (u64, &StrInfo)> {
        self.shards.values().flat_map(|t| t.strings.iter())
    }

    /// Gives all jump tables in address order.
    pub fn jumptables(&self) -> impl Iterator<Item = (JumpTableId, &Fact<JumpTable>)> {
        self.shards.values().flat_map(|t| t.jumptables.iter())
    }

    /// Gives each symbol name with its addresses, in name order. Each name gives the
    /// addresses of all shards in address order.
    #[must_use]
    pub fn names(&self) -> BTreeMap<&str, Vec<Address>> {
        let mut out: BTreeMap<&str, Vec<Address>> = BTreeMap::new();
        for t in self.shards.values() {
            for (name, addrs) in t.symbols.names() {
                out.entry(name).or_default().extend_from_slice(addrs);
            }
        }
        out
    }

    /// Gives a reference.
    #[must_use]
    pub fn ref_get(&self, key: &RefKey) -> Option<&Fact<Ref>> {
        self.at(key.from)?.refs.get(key)
    }

    /// Gives the symbol of `key` at `addr`.
    #[must_use]
    pub fn symbol(&self, addr: Address, key: SymKey) -> Option<&Symbol> {
        self.at(addr)?.symbols.get(addr, key)
    }

    /// Gives the string at the RAM offset `off`.
    #[must_use]
    pub fn string(&self, off: u64) -> Option<&StrInfo> {
        self.at_off(off)?.strings.get(off)
    }

    /// Gives the comment of `kind` at `addr`.
    #[must_use]
    pub fn comment(&self, addr: Address, kind: CommentKind) -> Option<&Fact<String>> {
        self.at(addr)?.comments.get(addr, kind)
    }

    /// Gives the IDs of the shards that the two sets do not share. Such a shard is in one set
    /// only, or each set has its own allocation of it.
    pub fn changed_shards<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = ShardId> + 'a {
        let ids: BTreeSet<ShardId> = self
            .shards
            .keys()
            .chain(other.shards.keys())
            .copied()
            .collect();
        ids.into_iter().filter(
            move |id| match (self.shards.get(id), other.shards.get(id)) {
                (Some(a), Some(b)) => !Arc::ptr_eq(a, b),
                _ => true,
            },
        )
    }

    /// Gives the why-record of a fact.
    #[must_use]
    pub fn why(&self, key: &FactKey) -> Option<Why> {
        self.of_key(key)?.why.get(key)
    }

    /// Gives all why-records, each shard in key order, the shards in address order.
    pub fn whys(&self) -> impl Iterator<Item = (FactKey, Why)> + '_ {
        self.shards.values().flat_map(|t| t.why.iter())
    }
}

/// Tells if a function of the shard `id` has a body range outside the shard.
fn is_wide(id: ShardId, t: &Tables) -> bool {
    let owned = t.funcs.ownership();
    let (Some((first, _)), Some((last, _))) = (owned.first(), owned.last()) else {
        return false;
    };
    id.range()
        .is_none_or(|r| first.first < r.first || last.last > r.last)
}
