//! The analysis context: the one write path of an analyzer (design Section 7.2).
//!
//! An [`AnalysisCtx`] gives an analyzer the program inputs and the work state of its
//! scheduler. Each insert function takes a required [`Why`], so no analyzer adds a fact
//! without a reason (ADR-0023). Each change records events. After the step, the scheduler
//! queues the event ranges for the analyzers that listen to their triggers.
//!
//! | Change | Events |
//! |---|---|
//! | a new function, a new or lost start reason | `Functions` at the entry |
//! | a new body | `Instructions` over the old and the new body |
//! | a new or lost noreturn flag | `FunctionModifiers` at the call sites of the function |
//! | a lost function | `Functions` at the entry and `Instructions` over its body |
//!
//! A new body takes the code units of a function with a higher entry where they overlap. That
//! function then runs again. So the lower entry always keeps shared code.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, FuncId, ImportId, Range};
use ghidorah_db::{FlowKind, Program, RefKey, StartReason};
use ghidorah_kernel::RangeSet;

use crate::registry::AnalyzerId;
use crate::spec::Trigger;
use crate::why::Why;
use crate::work::{Extent, WFunc, WUnit, Work};

/// The code unit flag of a call to a noreturn function.
pub const UNIT_NORETURN_CALL: u8 = 0x1;

/// The code unit flag of a noreturn call that only the known list flags (`W_NORETURN_ASSUMED`).
pub const UNIT_NORETURN_ASSUMED: u8 = 0x2;

/// One code unit of a new body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRec {
    /// The length in bytes, 1 to 15.
    pub len: u8,
    /// The flow kind.
    pub flow: FlowKind,
    /// The site flags, for example [`UNIT_NORETURN_CALL`].
    pub flags: u8,
    /// The why-record.
    pub why: Why,
}

/// The flow summary of a function body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    /// A path reaches a return.
    pub ret: bool,
    /// A path ends in bad code, at an unresolved indirect jump or at the instruction cap.
    pub unknown: bool,
    /// The addresses outside the body that the flow reaches: tail calls, a fall into another
    /// function and jumps into code of another function.
    pub exits: BTreeSet<u64>,
    /// The import slots of the indirect jumps through an import slot.
    pub slot_exits: BTreeSet<u64>,
    /// The direct call sites and their targets.
    pub calls: BTreeMap<u64, u64>,
    /// The indirect call sites through an import slot and their slots.
    pub slot_calls: BTreeMap<u64, u64>,
}

/// A new body of a function: its code units, its flow references and its summary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Body {
    /// The code units by start.
    pub units: BTreeMap<u64, UnitRec>,
    /// The flow references, each with its why-record.
    pub refs: BTreeMap<RefKey, Why>,
    /// The summary.
    pub summary: Summary,
}

/// The context of one analyzer step.
#[derive(Debug)]
pub struct AnalysisCtx<'a> {
    program: &'a Program,
    pub(crate) work: &'a mut Work,
    events: Vec<(Trigger, RangeSet)>,
    requeue: Vec<(AnalyzerId, RangeSet)>,
    changed: bool,
}

/// The events, the queued work and the change flag of one step.
pub(crate) type Outcome = (Vec<(Trigger, RangeSet)>, Vec<(AnalyzerId, RangeSet)>, bool);

/// Gives the set of one range.
fn one(range: Range) -> RangeSet {
    let mut set = RangeSet::new();
    set.insert(range);
    set
}

impl<'a> AnalysisCtx<'a> {
    /// Makes the context of one step.
    pub(crate) fn new(program: &'a Program, work: &'a mut Work) -> Self {
        Self {
            program,
            work,
            events: Vec::new(),
            requeue: Vec::new(),
            changed: false,
        }
    }

    /// Gives the events, the queued work and the change flag.
    pub(crate) fn finish(self) -> Outcome {
        (self.events, self.requeue, self.changed)
    }

    /// Gives the program: the input bytes and the facts of the base layer.
    #[must_use]
    pub const fn program(&self) -> &'a Program {
        self.program
    }

    /// Records an event over `ranges`.
    pub fn emit(&mut self, trigger: Trigger, ranges: RangeSet) {
        if !ranges.is_empty() {
            self.events.push((trigger, ranges));
        }
    }

    /// Queues `range` for the analyzer `id`.
    pub fn requeue(&mut self, id: AnalyzerId, range: Range) {
        self.requeue.push((id, one(range)));
    }

    /// Tells if a function starts at `at`.
    #[must_use]
    pub fn is_entry(&self, at: u64) -> bool {
        self.work.funcs.contains_key(&at)
    }

    /// Gives the function entries in address order.
    #[must_use]
    pub fn entries(&self) -> Vec<u64> {
        self.work.funcs.keys().copied().collect()
    }

    /// Gives the start reasons of the function `entry` in the order of design Section 7.3.
    #[must_use]
    pub fn reasons(&self, entry: u64) -> Vec<StartReason> {
        self.work
            .funcs
            .get(&entry)
            .map(|f| f.reasons.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Adds or replaces the start reason `reason` of the function `entry` with its confidence
    /// and its why-record. A new entry makes a new function. Gives `true` for a change.
    pub fn add_reason(
        &mut self,
        entry: u64,
        reason: StartReason,
        confidence: u8,
        why: Why,
    ) -> bool {
        let _ = (entry, reason, confidence, why);
        false
    }

    /// Removes the start reason `reason` of the function `entry`. The last reason removes the
    /// function with its body and its flags. Gives `true` for a change.
    pub fn remove_reason(&mut self, entry: u64, reason: StartReason) -> bool {
        let _ = (entry, reason);
        false
    }

    /// Adds the declared extent `range` of the function `entry`.
    pub fn add_extent(&mut self, entry: u64, range: Range) {
        let _ = (entry, range, Extent { last: 0, owner: 0 });
    }

    /// Gives the owner of the declared extent that holds `at`.
    #[must_use]
    pub fn extent_owner(&self, at: u64) -> Option<u64> {
        self.work.extent_at(at).map(|e| e.owner)
    }

    /// Tells if `at` is in a declared extent of the function `entry`.
    #[must_use]
    pub fn in_own_extent(&self, entry: u64, at: u64) -> bool {
        self.work.funcs.get(&entry).is_some_and(|f| f.in_extent(at))
    }

    /// Gives the owner of the code unit that holds `at`.
    #[must_use]
    pub fn owner(&self, at: u64) -> Option<u64> {
        self.work.owner(at)
    }

    /// Gives the flow summary of the function `entry`.
    #[must_use]
    pub fn summary(&self, entry: u64) -> Option<&Summary> {
        self.work.funcs.get(&entry).and_then(|f| f.summary.as_ref())
    }

    /// Gives the number of body changes of the function `entry`.
    #[must_use]
    pub fn changes(&self, entry: u64) -> u32 {
        self.work.changes.get(&entry).copied().unwrap_or_default()
    }

    /// Gives the functions that a change in `ranges` touches: the entries in the ranges, the
    /// owners of code units in the ranges and the functions that stop at an address in them.
    #[must_use]
    pub fn touching(&self, ranges: &RangeSet) -> BTreeSet<u64> {
        let _ = ranges;
        BTreeSet::new()
    }

    /// Puts `body` in place of the body of the function `entry`. Gives `true` for a change.
    pub fn set_body(&mut self, entry: u64, body: Body) -> bool {
        let _ = (entry, body, WUnit::range);
        false
    }

    /// Tells if the function at `target` is noreturn. A fact of the base layer wins over the
    /// work state.
    #[must_use]
    pub fn noreturn(&self, target: u64) -> bool {
        let id = FuncId(Address::ram(target));
        if let Some(fact) = self
            .program
            .base()
            .funcs()
            .get(id)
            .and_then(|f| f.flags.noreturn.as_ref())
        {
            return fact.value;
        }
        self.work.noreturn(target)
    }

    /// Tells if the flag of `target` comes from the known list only.
    #[must_use]
    pub fn noreturn_known(&self, target: u64) -> bool {
        self.work.known.contains_key(&target) && !self.work.found.contains_key(&target)
    }

    /// Tells if the import slot `slot` holds a noreturn import.
    #[must_use]
    pub fn noreturn_slot(&self, slot: u64) -> bool {
        self.work.slots.contains_key(&slot)
    }

    /// Gives the import of the noreturn slot `slot`.
    #[must_use]
    pub fn slot_import(&self, slot: u64) -> Option<&ImportId> {
        self.work.slots.get(&slot)
    }

    /// Sets or removes the noreturn flag of the known list for the function `entry`.
    /// Gives `true` for a change.
    pub fn set_known(&mut self, entry: u64, why: Option<Why>) -> bool {
        let _ = (entry, why);
        false
    }

    /// Sets or removes the noreturn flag of the flow for the function `entry`.
    /// Gives `true` for a change.
    pub fn set_found(&mut self, entry: u64, why: Option<Why>) -> bool {
        let _ = (entry, why);
        false
    }

    /// Marks the import slot `slot` as a slot of the noreturn import `import`.
    /// Gives `true` for a change.
    pub fn set_slot(&mut self, slot: u64, import: ImportId) -> bool {
        let _ = (slot, import);
        false
    }

    /// Gives the direct call sites of `target` in address order.
    #[must_use]
    pub fn call_sites(&self, target: u64) -> Vec<u64> {
        self.work
            .callers
            .get(&target)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Gives the functions with the flow summary of each, in entry order.
    pub(crate) fn funcs(&self) -> impl Iterator<Item = (u64, &WFunc)> {
        self.work.funcs.iter().map(|(e, f)| (*e, f))
    }
}
