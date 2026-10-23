//! The program invariants: an executable specification (design Section 3.11).
//!
//! [`Program::check_invariants`] runs after each commit under `debug_assertions` and after
//! each step of the model tests (AC-123). It gives one [`Violation`] per broken rule:
//!
//! | # | Rule | Violations |
//! |---|---|---|
//! | 1 | The from-index and the to-index of the references hold the same set. | `RefIndex` |
//! | 2 | Each analysis reference starts at a code unit or a data definition. | `RefFrom` |
//! | 3 | Each body holds its entry. Bodies of one layer are disjoint. The ownership map equals the union of the bodies. | `FuncEntry`, `FuncOverlap`, `Ownership` |
//! | 4 | Each address with symbols has one primary symbol. The name index equals the symbols. | `Primary`, `NameIndex` |
//! | 5 | Code units of one layer do not overlap. Data definitions of one layer do not overlap. | `UnitOverlap`, `DataOverlap` |
//! | 6 | Each analysis fact has a why-record. Each premise exists. The premises make no cycle. | `NoWhy`, `WhyOrphan`, `Premise`, `PremiseCycle` |
//! | 7 | The events have one revision step at a time and end at `rev`. No epoch is above `rev`. | `EventRev`, `EpochAhead` |
//! | 8 | Each jump-table target and indirect target is an instruction start in code or an import. | `JumpTarget`, `CallTarget` |
//! | 9 | Each evidence entry and each ID member of a note parses as an ID. | `Evidence` |
//!
//! Rule 8 reads "instruction start" as an address in an executable region that no code unit
//! holds after its first byte. So a new agent target is valid before the re-analysis.
//!
//! Rule 2 checks the analysis layer only. A forward `AddRef` checks the source of an agent
//! reference. A later re-analysis can drop that code unit. Then the agent reference is an
//! orphan: it stays, and `analysis::orphans` reports it (design Section 3.9).

mod whys;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{Address, FuncId, JumpTableId, NoteId, Range, Rev};
use ghidorah_loader::Perms;

use crate::edit::{Layer, is_id, starts_unit};
use crate::epochs::Table;
use crate::funcs::Function;
use crate::notes::{Note, NoteSet, SetMembers};
use crate::overrides::FlowOverride;
use crate::program::{Program, Tables};
use crate::refs::RefKey;
use crate::symbols::Symbol;
use crate::why::FactKey;

/// A broken program invariant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Violation {
    /// Rule 1: the from-index and the to-index of a layer differ.
    RefIndex {
        /// The layer.
        layer: Layer,
    },
    /// Rule 2: no code unit and no data definition starts at the source of an analysis
    /// reference.
    RefFrom {
        /// The layer of the reference.
        layer: Layer,
        /// The source address.
        from: Address,
    },
    /// Rule 3: the body of a function does not hold its entry.
    FuncEntry {
        /// The layer.
        layer: Layer,
        /// The function.
        func: FuncId,
    },
    /// Rule 3: the body of a function overlaps a body of another function of the layer.
    FuncOverlap {
        /// The layer.
        layer: Layer,
        /// The function with the higher entry.
        func: FuncId,
    },
    /// Rule 3: the ownership map of a layer differs from the union of its bodies.
    Ownership {
        /// The layer.
        layer: Layer,
    },
    /// Rule 4: an address with symbols does not have exactly one primary symbol.
    Primary {
        /// The layer.
        layer: Layer,
        /// The address.
        addr: Address,
        /// The number of primary symbols.
        count: usize,
    },
    /// Rule 4: the name index of a layer differs from its symbols for a name.
    NameIndex {
        /// The layer.
        layer: Layer,
        /// The name.
        name: String,
    },
    /// Rule 5: a code unit overlaps the next code unit of the layer.
    UnitOverlap {
        /// The layer.
        layer: Layer,
        /// The start of the first unit.
        at: u64,
    },
    /// Rule 5: a data definition overlaps the next data definition of the layer.
    DataOverlap {
        /// The layer.
        layer: Layer,
        /// The start of the first definition.
        at: u64,
    },
    /// Rule 6: an analysis fact has no why-record.
    NoWhy {
        /// The fact.
        key: FactKey,
    },
    /// Rule 6: a why-record names no analysis fact.
    WhyOrphan {
        /// The key of the record.
        key: FactKey,
    },
    /// Rule 6: a premise does not exist.
    Premise {
        /// The fact.
        key: FactKey,
        /// The premise.
        premise: FactKey,
    },
    /// Rule 6: a premise closes a cycle of premises.
    PremiseCycle {
        /// The fact.
        key: FactKey,
        /// The premise.
        premise: FactKey,
    },
    /// Rule 7: an event breaks the revision order, or the last event is not at `rev`.
    EventRev {
        /// The revision of the event.
        rev: Rev,
    },
    /// Rule 7: the epoch of a table is above `rev`.
    EpochAhead {
        /// The table.
        table: Table,
    },
    /// Rule 8: a jump-table target is not an instruction start in code and not an import.
    JumpTarget {
        /// The layer.
        layer: Layer,
        /// The jump table.
        table: JumpTableId,
        /// The target.
        target: Address,
    },
    /// Rule 8: an indirect target of a flow override is not an instruction start in code
    /// and not an import.
    CallTarget {
        /// The layer.
        layer: Layer,
        /// The instruction of the override.
        at: Address,
        /// The target.
        target: Address,
    },
    /// Rule 9: an evidence entry or an ID member of a note does not parse.
    Evidence {
        /// The note.
        note: NoteId,
        /// The text.
        text: String,
    },
}

impl Violation {
    /// Gives the number of the rule in design Section 3.11, 1 to 9.
    #[must_use]
    pub const fn rule(&self) -> u8 {
        match self {
            Self::RefIndex { .. } => 1,
            Self::RefFrom { .. } => 2,
            Self::FuncEntry { .. } | Self::FuncOverlap { .. } | Self::Ownership { .. } => 3,
            Self::Primary { .. } | Self::NameIndex { .. } => 4,
            Self::UnitOverlap { .. } | Self::DataOverlap { .. } => 5,
            Self::NoWhy { .. }
            | Self::WhyOrphan { .. }
            | Self::Premise { .. }
            | Self::PremiseCycle { .. } => 6,
            Self::EventRev { .. } | Self::EpochAhead { .. } => 7,
            Self::JumpTarget { .. } | Self::CallTarget { .. } => 8,
            Self::Evidence { .. } => 9,
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invariant {}: {self:?}", self.rule())
    }
}

/// Rule 1: compares the keys of the from-index and of the to-index.
fn ref_index(layer: Layer, mut from: Vec<RefKey>, mut to: Vec<RefKey>, out: &mut Vec<Violation>) {
    from.sort_unstable();
    to.sort_unstable();
    if from != to {
        out.push(Violation::RefIndex { layer });
    }
}

/// Rule 3: checks the bodies of the functions of a layer, in entry order, and the map.
fn bodies(
    layer: Layer,
    funcs: &[&Function],
    ownership: &[(Range, FuncId)],
    out: &mut Vec<Violation>,
) {
    let mut expect: Vec<(Range, FuncId)> = Vec::new();
    for f in funcs {
        if !(f.entry.is_ram() && f.body.contains(f.entry.off)) {
            out.push(Violation::FuncEntry {
                layer,
                func: f.id(),
            });
        }
        expect.extend(f.body.ranges().iter().map(|r| (*r, f.id())));
    }
    expect.sort_unstable();
    let mut overlapping = BTreeSet::new();
    for pair in expect.windows(2) {
        if let [(a, fa), (b, fb)] = pair
            && a.last >= b.first
        {
            overlapping.insert((*fa).max(*fb));
        }
    }
    for func in overlapping {
        out.push(Violation::FuncOverlap { layer, func });
    }
    if expect != ownership {
        out.push(Violation::Ownership { layer });
    }
}

/// Rule 4: checks the primary flags and the name index of the symbols of a layer.
fn symbols(
    layer: Layer,
    symbols: &[&Symbol],
    names: &[(&str, &[Address])],
    out: &mut Vec<Violation>,
) {
    let mut primaries: BTreeMap<Address, usize> = BTreeMap::new();
    for s in symbols {
        let count = primaries.entry(s.addr).or_default();
        *count = count.saturating_add(usize::from(s.primary));
    }
    for (addr, count) in primaries {
        if count != 1 {
            out.push(Violation::Primary { layer, addr, count });
        }
    }
    let held: BTreeSet<(&str, Address)> = symbols
        .iter()
        .map(|s| (s.name.value.as_str(), s.addr))
        .collect();
    let index: BTreeSet<(&str, Address)> = names
        .iter()
        .flat_map(|(name, addrs)| addrs.iter().map(move |a| (*name, *a)))
        .collect();
    let bad: BTreeSet<&str> = held
        .symmetric_difference(&index)
        .map(|(name, _)| *name)
        .collect();
    for name in bad {
        out.push(Violation::NameIndex {
            layer,
            name: name.to_string(),
        });
    }
}

/// Rule 5: checks that the spans `(start, len)` in start order do not overlap.
fn overlaps(layer: Layer, spans: &[(u64, u64)], data: bool, out: &mut Vec<Violation>) {
    for pair in spans.windows(2) {
        let [(at, len), (next, _)] = pair else {
            continue;
        };
        let last = len.checked_sub(1).and_then(|l| at.checked_add(l));
        if last.is_some_and(|last| *next <= last) {
            out.push(if data {
                Violation::DataOverlap { layer, at: *at }
            } else {
                Violation::UnitOverlap { layer, at: *at }
            });
        }
    }
}

/// Rule 9: checks the evidence entries and the ID members of the notes.
fn evidence(notes: &[&Note], out: &mut Vec<Violation>) {
    for n in notes {
        let members = match &n.set {
            Some(NoteSet {
                members: SetMembers::Ids(ids),
                ..
            }) => ids.as_slice(),
            _ => &[],
        };
        for text in n.evidence.iter().chain(members) {
            if !is_id(text) {
                out.push(Violation::Evidence {
                    note: n.id,
                    text: text.clone(),
                });
            }
        }
    }
}

/// All RAM offsets.
const ALL: Range = Range {
    first: 0,
    last: u64::MAX,
};

impl Program {
    /// Checks the invariants of design Section 3.11. Gives the violations in rule order.
    #[must_use]
    pub fn check_invariants(&self) -> Vec<Violation> {
        let mut out = Vec::new();
        let shards: Vec<&Tables> = self.analysis().shards().map(|(_, t)| t).collect();
        let layers: [(Layer, Vec<&Tables>); 2] =
            [(Layer::Base, vec![self.base()]), (Layer::Analysis, shards)];
        for (layer, ts) in &layers {
            let from = ts
                .iter()
                .flat_map(|t| t.refs().iter().map(|f| f.value.key))
                .collect();
            let to = ts.iter().flat_map(|t| t.refs().to_index()).collect();
            ref_index(*layer, from, to, &mut out);
        }
        for (_, t) in self.analysis().shards() {
            for r in t.refs().iter() {
                let from = r.value.key.from;
                if !starts_unit(self, from) {
                    out.push(Violation::RefFrom {
                        layer: Layer::Analysis,
                        from,
                    });
                }
            }
        }
        for (layer, ts) in &layers {
            let funcs: Vec<&Function> = ts.iter().flat_map(|t| t.funcs().iter()).collect();
            let mut owned: Vec<(Range, FuncId)> = ts
                .iter()
                .flat_map(|t| t.funcs().ownership().iter().copied())
                .collect();
            owned.sort_unstable();
            bodies(*layer, &funcs, &owned, &mut out);
        }
        for (layer, ts) in &layers {
            for t in ts {
                let syms: Vec<&Symbol> = t.symbols().iter().collect();
                let names: Vec<(&str, &[Address])> = t.symbols().names().collect();
                symbols(*layer, &syms, &names, &mut out);
            }
        }
        for (layer, ts) in &layers {
            let units: Vec<(u64, u64)> = ts
                .iter()
                .flat_map(|t| t.listing().units_in(ALL))
                .map(|(at, u)| (at, u64::from(u.len())))
                .collect();
            overlaps(*layer, &units, false, &mut out);
            let data: Vec<(u64, u64)> = ts
                .iter()
                .flat_map(|t| t.listing().data_defs())
                .map(|(at, d)| (at, u64::from(d.value.len)))
                .collect();
            overlaps(*layer, &data, true, &mut out);
        }
        whys::check(self, &mut out);
        self.check_events(&mut out);
        for (layer, t) in layers
            .iter()
            .flat_map(|(l, ts)| ts.iter().map(move |t| (*l, *t)))
        {
            for (table, jt) in t.jumptables().iter() {
                for target in jt
                    .value
                    .targets
                    .iter()
                    .filter(|a| !self.is_code_target(**a))
                {
                    out.push(Violation::JumpTarget {
                        layer,
                        table,
                        target: *target,
                    });
                }
            }
            for (at, flow) in t.overrides().iter() {
                if let FlowOverride::IndirectTargets(list) = &flow.value {
                    for target in list.iter().filter(|a| !self.is_code_target(**a)) {
                        out.push(Violation::CallTarget {
                            layer,
                            at,
                            target: *target,
                        });
                    }
                }
            }
        }
        let notes: Vec<&Note> = self.notes().iter().collect();
        evidence(&notes, &mut out);
        out
    }

    /// Rule 7: checks the revisions of the events and the epochs.
    fn check_events(&self, out: &mut Vec<Violation>) {
        let rev = self.rev();
        let events = self.events();
        let mut prev: Option<Rev> = None;
        for e in events.iter() {
            let step_ok = match prev {
                None => e.rev > events.lost(),
                Some(p) => e.rev == p || Some(e.rev.0) == p.0.checked_add(1),
            };
            if !step_ok || e.rev > rev {
                out.push(Violation::EventRev { rev: e.rev });
            }
            prev = Some(e.rev);
        }
        if let Some(last) = prev
            && last < rev
        {
            out.push(Violation::EventRev { rev: last });
        }
        for table in Table::ALL {
            if self.epochs().table(table) > rev {
                out.push(Violation::EpochAhead { table });
            }
        }
    }

    /// Tells if `target` is a valid jump-table target or indirect target (rule 8).
    ///
    /// A RAM target is in an executable region, and no code unit holds it after its first
    /// byte. Another target is the EXTERNAL address of an import.
    #[must_use]
    pub fn is_code_target(&self, target: Address) -> bool {
        if !target.is_ram() {
            return self.imports().values().any(|i| i.ext == target);
        }
        let exec = self
            .mem()
            .region_at(target.off)
            .is_some_and(|r| r.perms.contains(Perms::EXECUTE));
        let after_start = |u: Option<(u64, _)>| u.is_some_and(|(start, _)| start != target.off);
        let inside = after_start(self.base().listing().unit_containing(target.off))
            || after_start(self.analysis().unit_containing(target.off));
        exec && !inside
    }
}
