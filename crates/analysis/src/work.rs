//! The work state of a scheduler: the analysis facts before the publish step.
//!
//! The work state keeps one record for each function, code unit, flow reference and noreturn
//! flag, each with its [`Why`]. The keys are RAM offsets. Indexes give the owner of each code
//! unit, the call sites of each target and the functions that stop at an address.
//!
//! Rules:
//!
//! - Two code units never overlap. Each unit has one owner function.
//! - A flow reference starts at a code unit of the same owner.
//! - A function without a start reason does not exist.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, BinText, ImportId, Range};
use ghidorah_db::{FlowKind, Program, RefKey, StartReason, StrInfo};
use ghidorah_kernel::RangeSet;

use crate::analyzers::dataptr::CodePtrs;
use crate::analyzers::gapcomp::GapState;
use crate::analyzers::refs::DataRefs;
use crate::ctx::{Body, Summary, UnitRec};
use crate::irfacts::IrFacts;
use crate::why::Why;

/// One function of the work state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct WFunc {
    /// The start reasons, each with its confidence and its why-record.
    pub reasons: BTreeMap<StartReason, (u8, Why)>,
    /// The declared extents of the function: symbol sizes and FDE ranges.
    pub extents: Vec<Range>,
    /// The flow summary of the last disassembly, or `None` before it.
    pub summary: Option<Summary>,
    /// The starts of the code units of the function.
    pub units: BTreeSet<u64>,
    /// The flow references from the code units of the function.
    pub refs: BTreeSet<RefKey>,
}

impl WFunc {
    /// Gives the start reason of the highest confidence. A tie takes the first reason of
    /// design Section 7.3.
    pub fn primary(&self) -> Option<(StartReason, u8, &Why)> {
        let mut best: Option<(StartReason, u8, &Why)> = None;
        for (reason, (confidence, why)) in &self.reasons {
            if best.is_none_or(|(_, c, _)| *confidence > c) {
                best = Some((*reason, *confidence, why));
            }
        }
        best
    }

    /// Tells if `at` is in a declared extent of the function.
    pub fn in_extent(&self, at: u64) -> bool {
        self.extents.iter().any(|r| r.contains(at))
    }
}

/// One code unit of the work state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WUnit {
    /// The length in bytes.
    pub len: u8,
    /// The flow kind.
    pub flow: FlowKind,
    /// The site flags.
    pub flags: u8,
    /// The entry of the owner function. The why-record of the unit is
    /// [`crate::why::unit_why`] of the owner.
    pub owner: u64,
}

impl WUnit {
    /// Gives the addresses of the unit at `at`.
    pub fn range(&self, at: u64) -> Option<Range> {
        Range::with_len(at, u64::from(self.len))
    }
}

/// The declared extent of a function: a symbol size or an FDE range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Extent {
    /// The last address.
    pub last: u64,
    /// The entry of the function.
    pub owner: u64,
}

/// The import of an import slot and its EXTERNAL address.
pub(crate) type SlotImport = (ImportId, Address);

/// The work state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Work {
    /// The functions by entry.
    pub funcs: BTreeMap<u64, WFunc>,
    /// The code units by start.
    pub units: BTreeMap<u64, WUnit>,
    /// The flow references.
    pub refs: BTreeMap<RefKey, Why>,
    /// The noreturn flags from the known list, by function entry.
    pub known: BTreeMap<u64, Why>,
    /// The noreturn flags from the flow, by function entry.
    pub found: BTreeMap<u64, Why>,
    /// The import slots of the noreturn imports.
    pub slots: BTreeMap<u64, ImportId>,
    /// The declared extents by start. Two extents at one start keep the longer one.
    pub extents: BTreeMap<u64, Extent>,
    /// The functions whose flow stops at an address outside their body.
    pub exits: BTreeMap<u64, BTreeSet<u64>>,
    /// The call sites of each direct call target.
    pub callers: BTreeMap<u64, BTreeSet<u64>>,
    /// The indirect call sites of each import slot.
    pub slot_callers: BTreeMap<u64, BTreeSet<u64>>,
    /// The number of body changes of each function entry.
    pub changes: BTreeMap<u64, u64>,
    /// The import of each import slot of the binary. The first step fills it.
    pub import_slots: Option<BTreeMap<u64, SlotImport>>,
    /// The PLT area of the binary. The first step fills it.
    pub plt: Option<RangeSet>,
    /// The data references of operands and pointer slots.
    pub data: DataRefs,
    /// The strings by start, each with its why-record.
    pub strings: BTreeMap<u64, (StrInfo, Why)>,
    /// The facts of the IR-based analyzers.
    pub ir: IrFacts,
    /// The code pointers in data and the address-taken sites.
    pub codeptrs: CodePtrs,
    /// The state of the gap components.
    pub gapcomp: GapState,
    /// The cap of the code units of the program, or `None` for
    /// [`crate::analyzers::disasm::MAX_UNITS`].
    pub unit_cap: Option<u64>,
    /// `true` when a body stopped at the cap of the code units.
    pub capped: bool,
}

/// Gives the import of each import slot of `program`: the ELF slot map, then the slots of
/// the import rows.
///
/// The ELF slot map gives the import of a slot by its name. The row of that name gives the
/// import ID, so the order of the import list does not change the import of a slot.
pub(crate) fn import_slots(program: &Program) -> BTreeMap<u64, SlotImport> {
    let imports = &program.binary().imports;
    let name_of = |index: usize| {
        imports
            .get(index)
            .and_then(|i| i.name.as_ref())
            .map(BinText::as_bytes)
    };
    let by_name: BTreeMap<&[u8], SlotImport> = program
        .imports()
        .values()
        .filter(|row| row.id.lib().is_none())
        .filter_map(|row| Some((name_of(row.index)?, (row.id.clone(), row.ext))))
        .collect();
    let mut out = BTreeMap::new();
    for (slot, s) in ghidorah_loader::imports::slots(program.binary()) {
        if let Some(import) = name_of(s.import).and_then(|n| by_name.get(n)) {
            out.insert(slot, import.clone());
        }
    }
    for row in program.imports().values() {
        if let Some(slot) = row.slot.filter(Address::is_ram) {
            out.entry(slot.off)
                .or_insert_with(|| (row.id.clone(), row.ext));
        }
    }
    out
}

impl Work {
    /// Gives the start and the record of the code unit that holds `at`.
    pub fn unit_at(&self, at: u64) -> Option<(u64, &WUnit)> {
        let (start, unit) = self.units.range(..=at).next_back()?;
        unit.range(*start)?.contains(at).then_some((*start, unit))
    }

    /// Gives the owner of the code unit that holds `at`.
    pub fn owner(&self, at: u64) -> Option<u64> {
        self.unit_at(at).map(|(_, u)| u.owner)
    }

    /// Gives the starts and the owners of the code units that overlap `range`.
    pub fn overlapping(&self, range: Range) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        if let Some((start, unit)) = self.unit_at(range.first) {
            out.push((start, unit.owner));
        }
        if let Some(next) = range.first.checked_add(1)
            && next <= range.last
        {
            out.extend(
                self.units
                    .range(next..=range.last)
                    .map(|(a, u)| (*a, u.owner)),
            );
        }
        out
    }

    /// Gives the body of the function `entry`: its code units, or its entry byte alone.
    pub fn body(&self, entry: u64) -> RangeSet {
        let mut body = RangeSet::new();
        if let Some(f) = self.funcs.get(&entry) {
            for at in &f.units {
                if let Some(r) = self.units.get(at).and_then(|u| u.range(*at)) {
                    body.insert(r);
                }
            }
        }
        if !body.contains(entry) {
            body.insert(Range::single(entry));
        }
        body
    }

    /// Tells if the function `entry` is noreturn in the work state.
    pub fn noreturn(&self, entry: u64) -> bool {
        self.known.contains_key(&entry) || self.found.contains_key(&entry)
    }

    /// Gives the start and the extent that holds `at`: the one with the last start at or
    /// below `at`.
    pub fn extent_at(&self, at: u64) -> Option<(u64, Extent)> {
        let (start, e) = self.extents.range(..=at).next_back()?;
        (at <= e.last).then_some((*start, *e))
    }

    /// Removes the code unit at `at` with its references and its call-site indexes.
    /// Gives its range.
    pub fn drop_unit(&mut self, at: u64) -> Option<Range> {
        let unit = self.units.remove(&at)?;
        let range = unit.range(at);
        let Some(f) = self.funcs.get_mut(&unit.owner) else {
            return range;
        };
        f.units.remove(&at);
        let gone: Vec<RefKey> = f
            .refs
            .iter()
            .filter(|k| k.from == Address::ram(at))
            .copied()
            .collect();
        for key in gone {
            f.refs.remove(&key);
            self.refs.remove(&key);
        }
        if let Some(s) = &f.summary {
            if let Some(t) = s.calls.get(&at) {
                remove_from(&mut self.callers, *t, at);
            }
            if let Some(slot) = s.slot_calls.get(&at) {
                remove_from(&mut self.slot_callers, *slot, at);
            }
        }
        range
    }

    /// Removes the body of the function `entry`: its units, references and indexes.
    pub fn clear_body(&mut self, entry: u64) {
        let units: Vec<u64> = self
            .funcs
            .get(&entry)
            .map(|f| f.units.iter().copied().collect())
            .unwrap_or_default();
        for at in units {
            let _ = self.drop_unit(at);
        }
        let Some(f) = self.funcs.get_mut(&entry) else {
            return;
        };
        if let Some(s) = f.summary.take() {
            for x in &s.exits {
                remove_from(&mut self.exits, *x, entry);
            }
        }
    }

    /// Puts the units and references of `body` for the function `entry`. A unit that
    /// overlaps a unit of a lower entry stays out. A unit of a higher entry that overlaps a
    /// new unit goes. Gives the owners of the units that go, with their ranges.
    pub fn put_body(&mut self, entry: u64, body: Body) -> Vec<(u64, Range)> {
        let mut evicted = Vec::new();
        let mut kept = BTreeSet::new();
        for (at, rec) in body.units {
            let Some(range) = Range::with_len(at, u64::from(rec.len)) else {
                continue;
            };
            let others = self.overlapping(range);
            if others.iter().any(|(_, o)| *o < entry) {
                continue;
            }
            for (start, owner) in others {
                if let Some(r) = self.drop_unit(start) {
                    evicted.push((owner, r));
                }
            }
            let UnitRec { len, flow, flags } = rec;
            self.units.insert(
                at,
                WUnit {
                    len,
                    flow,
                    flags,
                    owner: entry,
                },
            );
            kept.insert(at);
        }
        let Some(f) = self.funcs.get_mut(&entry) else {
            return evicted;
        };
        for (key, why) in body.refs {
            if kept.contains(&key.from.off) {
                f.refs.insert(key);
                self.refs.insert(key, why);
            }
        }
        for x in &body.summary.exits {
            self.exits.entry(*x).or_default().insert(entry);
        }
        for (site, target) in &body.summary.calls {
            if kept.contains(site) {
                self.callers.entry(*target).or_default().insert(*site);
            }
        }
        for (site, slot) in &body.summary.slot_calls {
            if kept.contains(site) {
                self.slot_callers.entry(*slot).or_default().insert(*site);
            }
        }
        f.units = kept;
        f.summary = Some(body.summary);
        evicted
    }

    /// Tells if `body` equals the current body of the function `entry`.
    pub fn same_body(&self, entry: u64, body: &Body) -> bool {
        let Some(f) = self.funcs.get(&entry) else {
            return false;
        };
        if f.summary.as_ref() != Some(&body.summary)
            || f.units.len() != body.units.len()
            || f.refs.len() != body.refs.len()
        {
            return false;
        }
        let units = body.units.iter().all(|(at, rec)| {
            self.units.get(at).is_some_and(|u| {
                u.owner == entry && u.len == rec.len && u.flow == rec.flow && u.flags == rec.flags
            })
        });
        units
            && body
                .refs
                .iter()
                .all(|(k, why)| f.refs.contains(k) && self.refs.get(k) == Some(why))
    }
}

/// Removes `item` from the set of `key`. An empty set goes.
fn remove_from(map: &mut BTreeMap<u64, BTreeSet<u64>>, key: u64, item: u64) {
    if let Some(set) = map.get_mut(&key) {
        set.remove(&item);
        if set.is_empty() {
            map.remove(&key);
        }
    }
}
