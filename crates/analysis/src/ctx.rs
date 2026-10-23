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
//! function then runs again. So the lower entry always keeps shared code. When a body lets an
//! address go, each function whose flow stops there runs again.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, FuncId, ImportId, Range};
use ghidorah_db::{FlowKind, Program, RefKey, StartReason};
use ghidorah_kernel::RangeSet;

use crate::registry::AnalyzerId;
use crate::spec::Trigger;
use crate::why::Why;
use crate::work::{Extent, WFunc, Work, import_slots};

/// The code unit flag of a call to a noreturn function.
pub const UNIT_NORETURN_CALL: u8 = 0x1;

/// The code unit flag of a noreturn call that only the known list flags (`W_NORETURN_ASSUMED`).
pub const UNIT_NORETURN_ASSUMED: u8 = 0x2;

/// The code unit flag of an indirect jump or call whose target is the constant 0.
///
/// An example is a weak symbol that the static linker sets to 0. A guard skips the site, so
/// the site has no target ([`crate::slotsite`]).
pub const UNIT_NULL_TARGET: u8 = 0x4;

/// One code unit of a new body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRec {
    /// The length in bytes, 1 to 15.
    pub len: u8,
    /// The flow kind.
    pub flow: FlowKind,
    /// The site flags, for example [`UNIT_NORETURN_CALL`].
    pub flags: u8,
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

/// Gives the set of single addresses.
fn points(items: impl IntoIterator<Item = u64>) -> RangeSet {
    let mut set = RangeSet::new();
    for at in items {
        set.insert(Range::single(at));
    }
    set
}

impl<'a> AnalysisCtx<'a> {
    /// Makes the context of one step. The first step fills the import slot index.
    pub(crate) fn new(program: &'a Program, work: &'a mut Work) -> Self {
        if work.import_slots.is_none() {
            work.import_slots = Some(import_slots(program));
        }
        if work.plt.is_none() {
            work.plt = Some(crate::code::plt_area(program));
        }
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

    /// Records that the step changes the work state, so the publish step runs.
    pub(crate) const fn touch(&mut self) {
        self.changed = true;
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

    /// Queues `Disasm` for each function whose flow stops in `ranges`.
    fn release(&mut self, ranges: &RangeSet) {
        let mut found = BTreeSet::new();
        for r in ranges.ranges() {
            for funcs in self.work.exits.range(r.first..=r.last).map(|(_, f)| f) {
                found.extend(funcs.iter().copied());
            }
        }
        for f in found {
            self.requeue(AnalyzerId::Disasm, Range::single(f));
        }
    }

    /// Tells if `at` is in the PLT area: a PLT section or a stub that the loader finds.
    #[must_use]
    pub fn in_plt(&self, at: u64) -> bool {
        self.work.plt.as_ref().is_some_and(|r| r.contains(at))
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

    /// Adds or replaces the start reason `reason` of the function `entry` with its confidence
    /// and its why-record. A new entry makes a new function. Gives `true` for a change.
    pub fn add_reason(
        &mut self,
        entry: u64,
        reason: StartReason,
        confidence: u8,
        why: Why,
    ) -> bool {
        let f = self.work.funcs.entry(entry).or_default();
        let new = (confidence.min(100), why);
        if f.reasons.get(&reason) == Some(&new) {
            return false;
        }
        f.reasons.insert(reason, new);
        self.changed = true;
        self.emit(Trigger::Functions, points([entry]));
        true
    }

    /// Removes the start reason `reason` of the function `entry`. The last reason removes the
    /// function with its body and its flags. Gives `true` for a change.
    pub fn remove_reason(&mut self, entry: u64, reason: StartReason) -> bool {
        let Some(f) = self.work.funcs.get_mut(&entry) else {
            return false;
        };
        if f.reasons.remove(&reason).is_none() {
            return false;
        }
        let last = f.reasons.is_empty();
        self.changed = true;
        self.emit(Trigger::Functions, points([entry]));
        if last {
            self.remove_func(entry);
        }
        true
    }

    /// Removes the function `entry` with its body, its extents and its flags.
    fn remove_func(&mut self, entry: u64) {
        let old = self.work.body(entry);
        let _ = self.set_known(entry, None);
        let _ = self.set_found(entry, None);
        self.work.clear_body(entry);
        self.work.funcs.remove(&entry);
        self.work.extents.retain(|_, e| e.owner != entry);
        self.emit(Trigger::Instructions, old.clone());
        self.release(&old);
    }

    /// Adds the declared extent `range` of the function `entry`. The function must exist.
    pub fn add_extent(&mut self, entry: u64, range: Range) {
        let Some(f) = self.work.funcs.get_mut(&entry) else {
            return;
        };
        if f.extents.contains(&range) {
            return;
        }
        f.extents.push(range);
        let slot = self.work.extents.entry(range.first).or_insert(Extent {
            last: range.last,
            owner: entry,
        });
        if range.last > slot.last {
            *slot = Extent {
                last: range.last,
                owner: entry,
            };
        }
        self.changed = true;
    }

    /// Gives the owner of the declared extent that holds `at`.
    #[must_use]
    pub fn extent_owner(&self, at: u64) -> Option<u64> {
        self.work.extent_at(at).map(|(_, e)| e.owner)
    }

    /// Gives the owner of a declared extent of another function that holds `at` and not the
    /// entry of the function `entry`. An extent that holds both, for example the FDE of a PLT
    /// section, does not stop the flow. An extent of `entry` itself does not either.
    #[must_use]
    pub fn foreign_extent(&self, entry: u64, at: u64) -> Option<u64> {
        let (start, e) = self.work.extent_at(at)?;
        let holds_entry = start <= entry && entry <= e.last;
        (e.owner != entry && !holds_entry && !self.in_own_extent(entry, at)).then_some(e.owner)
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
    pub fn changes(&self, entry: u64) -> u64 {
        self.work.changes.get(&entry).copied().unwrap_or_default()
    }

    /// Gives the functions that a change in `ranges` touches. These are the entries in the
    /// ranges and the owners of code units in them. The functions that stop at an address in
    /// them are also in the set.
    #[must_use]
    pub fn touching(&self, ranges: &RangeSet) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        for r in ranges.ranges() {
            out.extend(self.work.funcs.range(r.first..=r.last).map(|(e, _)| *e));
            out.extend(self.work.overlapping(*r).into_iter().map(|(_, o)| o));
            for funcs in self.work.exits.range(r.first..=r.last).map(|(_, f)| f) {
                out.extend(funcs.iter().copied());
            }
        }
        out.retain(|e| self.work.funcs.contains_key(e));
        out
    }

    /// Puts `body` in place of the body of the function `entry`. Gives `true` for a change.
    pub fn set_body(&mut self, entry: u64, body: Body) -> bool {
        if !self.work.funcs.contains_key(&entry) || self.work.same_body(entry, &body) {
            return false;
        }
        let old = self.work.body(entry);
        self.work.clear_body(entry);
        let evicted = self.work.put_body(entry, body);
        let count = self.work.changes.entry(entry).or_default();
        *count = count.saturating_add(1);
        let new = self.work.body(entry);
        self.changed = true;
        self.emit(Trigger::Instructions, old.union(&new));
        self.release(&old.subtract(&new));
        let mut gone = RangeSet::new();
        for (owner, range) in evicted {
            gone.insert(range);
            self.requeue(AnalyzerId::Disasm, Range::single(owner));
        }
        self.emit(Trigger::Instructions, gone);
        true
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

    /// Gives the import of the import slot `slot` with its EXTERNAL address.
    #[must_use]
    pub fn slot_target(&self, slot: u64) -> Option<(&ImportId, Address)> {
        self.work
            .import_slots
            .as_ref()?
            .get(&slot)
            .map(|(id, ext)| (id, *ext))
    }

    /// Gives the import slots of the binary with their imports, in slot order.
    #[must_use]
    pub fn import_slots(&self) -> Vec<(u64, ImportId)> {
        self.work
            .import_slots
            .iter()
            .flatten()
            .map(|(slot, (id, _))| (*slot, id.clone()))
            .collect()
    }

    /// Sets or removes the noreturn flag of the known list for the function `entry`.
    /// Gives `true` for a change.
    pub fn set_known(&mut self, entry: u64, why: Option<Why>) -> bool {
        let old = self.work.known.get(&entry).cloned();
        if old == why || (why.is_some() && !self.work.funcs.contains_key(&entry)) {
            return false;
        }
        match why {
            Some(w) => self.work.known.insert(entry, w),
            None => self.work.known.remove(&entry),
        };
        self.flag_changed(entry);
        true
    }

    /// Sets or removes the noreturn flag of the flow for the function `entry`.
    /// Gives `true` for a change.
    pub fn set_found(&mut self, entry: u64, why: Option<Why>) -> bool {
        let old = self.work.found.get(&entry).cloned();
        if old == why || (why.is_some() && !self.work.funcs.contains_key(&entry)) {
            return false;
        }
        match why {
            Some(w) => self.work.found.insert(entry, w),
            None => self.work.found.remove(&entry),
        };
        self.flag_changed(entry);
        true
    }

    /// Records the `FunctionModifiers` event of a new flag of `entry` at its call sites.
    fn flag_changed(&mut self, entry: u64) {
        self.changed = true;
        let sites = self.call_sites(entry);
        self.emit(Trigger::FunctionModifiers, points(sites));
    }

    /// Marks the import slot `slot` as a slot of the noreturn import `import`.
    /// Gives `true` for a change.
    pub fn set_slot(&mut self, slot: u64, import: ImportId) -> bool {
        if self.work.slots.get(&slot) == Some(&import) {
            return false;
        }
        self.work.slots.insert(slot, import);
        self.changed = true;
        let sites: Vec<u64> = self
            .work
            .slot_callers
            .get(&slot)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        self.emit(Trigger::FunctionModifiers, points(sites));
        true
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

    /// Gives the functions in entry order.
    pub(crate) fn funcs(&self) -> impl Iterator<Item = (u64, &WFunc)> {
        self.work.funcs.iter().map(|(e, f)| (*e, f))
    }
}
