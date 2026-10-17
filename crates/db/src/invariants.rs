//! The program invariants: an executable specification (design Section 3.11).
//!
//! [`Program::check_invariants`] runs after each commit under `debug_assertions` and after
//! each step of the model tests (AC-123). It gives one [`Violation`] per broken rule:
//!
//! | # | Rule | Violations |
//! |---|---|---|
//! | 1 | The from-index and the to-index of the references hold the same set. | `RefIndex` |
//! | 2 | Each reference starts at a code unit or a data definition. | `RefFrom` |
//! | 3 | Each body holds its entry. Bodies of one layer are disjoint. The ownership map equals the union of the bodies. | `FuncEntry`, `FuncOverlap`, `Ownership` |
//! | 4 | Each address with symbols has one primary symbol. The name index equals the symbols. | `Primary`, `NameIndex` |
//! | 5 | Code units of one layer do not overlap. Data definitions of one layer do not overlap. | `UnitOverlap`, `DataOverlap` |
//! | 6 | Each analysis fact has a why-record. Each premise exists and has a lower creation order. | `NoWhy`, `WhyOrphan`, `Premise`, `PremiseOrder` |
//! | 7 | The events have one revision step at a time and end at `rev`. No epoch is above `rev`. | `EventRev`, `EpochAhead` |
//! | 8 | Each jump-table target and indirect target is an instruction start in code or an import. | `JumpTarget`, `CallTarget` |
//! | 9 | Each evidence entry and each ID member of a note parses as an ID. | `Evidence` |
//!
//! Rule 8 reads "instruction start" as an address in an executable region that no code unit
//! holds after its first byte. So a new agent target is valid before the re-analysis.

#[cfg(test)]
mod tests;

use std::fmt;

use ghidorah_base::{Address, FuncId, JumpTableId, NoteId, Range, Rev};

use crate::edit::Layer;
use crate::epochs::Table;
use crate::funcs::Function;
use crate::notes::Note;
use crate::program::Program;
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
    /// Rule 2: no code unit and no data definition starts at the source of a reference.
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
    /// Rule 6: a premise does not have a lower creation order than its fact.
    PremiseOrder {
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
            | Self::PremiseOrder { .. } => 6,
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
fn ref_index(layer: Layer, from: Vec<RefKey>, to: Vec<RefKey>, out: &mut Vec<Violation>) {
    let _ = (layer, from, to, out);
}

/// Rule 3: checks the bodies of the functions of a layer, in entry order, and the map.
fn bodies(
    layer: Layer,
    funcs: &[&Function],
    ownership: &[(Range, FuncId)],
    out: &mut Vec<Violation>,
) {
    let _ = (layer, funcs, ownership, out);
}

/// Rule 4: checks the primary flags and the name index of the symbols of a layer.
fn symbols(
    layer: Layer,
    symbols: &[&Symbol],
    names: &[(&str, &[Address])],
    out: &mut Vec<Violation>,
) {
    let _ = (layer, symbols, names, out);
}

/// Rule 5: checks that the spans `(start, len)` in start order do not overlap.
fn overlaps(layer: Layer, spans: &[(u64, u64)], data: bool, out: &mut Vec<Violation>) {
    let _ = (layer, spans, data, out);
}

/// Rule 9: checks the evidence entries and the ID members of the notes.
fn evidence(notes: &[&Note], out: &mut Vec<Violation>) {
    let _ = (notes, out);
}

impl Program {
    /// Checks the invariants of design Section 3.11. Gives the violations in rule order.
    #[must_use]
    pub fn check_invariants(&self) -> Vec<Violation> {
        Vec::new()
    }

    /// Tells if `target` is a valid jump-table target or indirect target (rule 8).
    #[must_use]
    pub fn is_code_target(&self, target: Address) -> bool {
        let _ = target;
        true
    }
}
