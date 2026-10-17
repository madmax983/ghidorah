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

use ghidorah_base::{ImportId, Range};
use ghidorah_db::{FlowKind, RefKey, StartReason};
use ghidorah_kernel::RangeSet;

use crate::ctx::Summary;
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
    /// The entry of the owner function.
    pub owner: u64,
    /// The why-record.
    pub why: Why,
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
    pub changes: BTreeMap<u64, u32>,
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

    /// Gives the extent that holds `at`: the one with the last start at or below `at`.
    pub fn extent_at(&self, at: u64) -> Option<Extent> {
        let (_, e) = self.extents.range(..=at).next_back()?;
        (at <= e.last).then_some(*e)
    }
}
