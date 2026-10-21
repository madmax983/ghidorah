//! Table epochs and function epochs (design Section 3.8).
//!
//! The epoch of a table is the revision of its last change. Caches of derived data use the
//! key `(FuncId, func_epoch)`. The epoch of a function is the highest epoch of the facts
//! that its derived views read:
//!
//! - the analysis layer,
//! - the record of the function: create, delete, signature, noreturn, the name at the
//!   entry and the variable facts,
//! - the address facts in its body: references from the body, flow overrides, jump tables,
//!   data definitions, names and comments,
//! - the record of each callee: a call reference or a jump reference from the body names
//!   it. A tail jump to the entry of another function is a jump reference. The record at
//!   each other jump target counts too, so a new function there changes the epoch.
//!
//! The listing, function, symbol, reference, string, comment and variable tables merge the
//! analysis layer. So their epoch is at least the epoch of the analysis table.
//!
//! | Edit | Table |
//! |---|---|
//! | `SetName` | `symbols` |
//! | `SetComment` | `comments` |
//! | `SetVarFact` | `vars` |
//! | `AddRef`, `RemoveRef` | `refs` |
//! | `CreateFunction`, `DeleteFunction`, `SetSignature`, `SetNoreturn` | `functions` |
//! | `SetJumpTable`, `SetFlowOverride`, `SetDataDef` | `listing` |
//! | `WriteNote`, `DeleteNote` | `notes` |
//! | `ReplaceAnalysis` | `analysis` |

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{Address, FuncId, Range, Rev, TxId};
use ghidorah_kernel::RangeSet;

use crate::edit::Edit;
use crate::events::Event;
use crate::program::Program;
use crate::refs::RefType;
use crate::why::FactKey;

/// A table with an epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Table {
    /// The memory map.
    Memory,
    /// Code units, data definitions, jump tables and flow overrides.
    Listing,
    /// Functions, signatures and noreturn flags.
    Functions,
    /// Symbols.
    Symbols,
    /// References.
    Refs,
    /// Strings.
    Strings,
    /// Comments.
    Comments,
    /// Notes and named sets.
    Notes,
    /// Variable facts.
    Vars,
    /// Types.
    Types,
    /// The analysis layer.
    Analysis,
}

impl Table {
    /// All tables in the order of design Section 3.8.
    pub const ALL: [Self; 11] = [
        Self::Memory,
        Self::Listing,
        Self::Functions,
        Self::Symbols,
        Self::Refs,
        Self::Strings,
        Self::Comments,
        Self::Notes,
        Self::Vars,
        Self::Types,
        Self::Analysis,
    ];

    /// Gives the output name, for example `functions`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Listing => "listing",
            Self::Functions => "functions",
            Self::Symbols => "symbols",
            Self::Refs => "refs",
            Self::Strings => "strings",
            Self::Comments => "comments",
            Self::Notes => "notes",
            Self::Vars => "vars",
            Self::Types => "types",
            Self::Analysis => "analysis",
        }
    }

    /// Gives the table of an output name. An unknown name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }

    /// Tells if reads of the table merge the analysis layer.
    #[must_use]
    pub const fn merges_analysis(self) -> bool {
        !matches!(
            self,
            Self::Memory | Self::Notes | Self::Types | Self::Analysis
        )
    }
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The epochs of the tables, of the function records and of the address facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Epochs {
    tables: BTreeMap<Table, Rev>,
    funcs: BTreeMap<FuncId, Rev>,
    addrs: BTreeMap<Address, Rev>,
}

impl Epochs {
    /// Gives the revision of the last change of the table itself, or 0.
    #[must_use]
    pub fn table(&self, table: Table) -> Rev {
        self.tables.get(&table).copied().unwrap_or_default()
    }

    /// Gives the revision of the last change of the record facts of a function, or 0.
    #[must_use]
    pub fn func(&self, func: FuncId) -> Rev {
        self.funcs.get(&func).copied().unwrap_or_default()
    }

    /// Gives the revision of the last change of a fact at an address, or 0.
    #[must_use]
    pub fn addr(&self, addr: Address) -> Rev {
        self.addrs.get(&addr).copied().unwrap_or_default()
    }

    /// Gives the highest revision of the address facts in `ranges`, or 0.
    #[must_use]
    pub fn in_ranges(&self, ranges: &RangeSet) -> Rev {
        ranges
            .ranges()
            .iter()
            .filter_map(|r| {
                self.addrs
                    .range(Address::ram(r.first)..=Address::ram(r.last))
                    .map(|(_, rev)| *rev)
                    .max()
            })
            .max()
            .unwrap_or_default()
    }

    /// Records the changes of one commit at `rev`.
    pub(crate) fn record(&mut self, rev: Rev, touch: &Touch) {
        for table in touch.tables.keys() {
            self.tables.insert(*table, rev);
        }
        for func in &touch.funcs {
            self.funcs.insert(*func, rev);
        }
        for addr in &touch.addrs {
            self.addrs.insert(*addr, rev);
        }
    }
}

/// The changes of one commit: tables, function records, addresses and fact keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Touch {
    /// The RAM ranges and fact keys of each changed table.
    pub tables: BTreeMap<Table, (RangeSet, BTreeSet<FactKey>)>,
    /// The functions whose record facts change.
    pub funcs: BTreeSet<FuncId>,
    /// The addresses whose facts change.
    pub addrs: BTreeSet<Address>,
}

/// Gives the table of a fact key.
const fn key_table(key: &FactKey) -> Table {
    match key {
        FactKey::CodeUnit(_)
        | FactKey::Data(_)
        | FactKey::JumpTable(_)
        | FactKey::FlowOverride(_) => Table::Listing,
        FactKey::Symbol(..) => Table::Symbols,
        FactKey::Func(_) | FactKey::Signature(_) | FactKey::Noreturn(_) => Table::Functions,
        FactKey::Ref(_) => Table::Refs,
        FactKey::Comment(..) => Table::Comments,
        FactKey::Str(_) => Table::Strings,
        FactKey::Var(_) => Table::Vars,
        FactKey::Note(_) => Table::Notes,
        FactKey::Import(_)
        | FactKey::Export(_)
        | FactKey::Entry(_)
        | FactKey::Reloc(_)
        | FactKey::Fde(_) => Table::Memory,
    }
}

/// Gives the address of the fact of a key, when it has one.
const fn key_addr(key: &FactKey) -> Option<Address> {
    match key {
        FactKey::CodeUnit(o) | FactKey::Data(o) => Some(Address::ram(*o)),
        FactKey::Symbol(a, _) | FactKey::Comment(a, _) | FactKey::FlowOverride(a) => Some(*a),
        FactKey::Func(f) | FactKey::Signature(f) | FactKey::Noreturn(f) => Some(f.0),
        FactKey::Ref(r) => Some(r.from),
        FactKey::JumpTable(j) => Some(j.0),
        FactKey::Str(s) => Some(s.0),
        _ => None,
    }
}

/// Gives the function whose record facts a key changes. A name at an entry, a variable and
/// the target of a reference name a function too.
const fn key_func(key: &FactKey) -> Option<FuncId> {
    match key {
        FactKey::Func(f) | FactKey::Signature(f) | FactKey::Noreturn(f) => Some(*f),
        FactKey::Symbol(a, _) => Some(FuncId(*a)),
        FactKey::Var(v) => Some(v.func),
        FactKey::Ref(r) => Some(FuncId(r.to)),
        _ => None,
    }
}

impl Touch {
    /// Adds the changes of `edit`. A commit adds each edit and its inverse.
    pub(crate) fn add(&mut self, edit: &Edit) {
        if let Edit::ReplaceAnalysis(_) = edit {
            self.tables.entry(Table::Analysis).or_default();
        }
        if let Edit::CreateFunction(r) = edit {
            let (ranges, _) = self.tables.entry(Table::Functions).or_default();
            *ranges = ranges.union(&r.func.body);
        }
        for key in edit.keys() {
            let (ranges, ids) = self.tables.entry(key_table(&key)).or_default();
            if let Some(a) = key_addr(&key) {
                if a.is_ram() {
                    ranges.insert(Range::single(a.off));
                }
                self.addrs.insert(a);
            }
            if let Some(f) = key_func(&key) {
                self.funcs.insert(f);
            }
            ids.insert(key);
        }
    }

    /// Gives the events of the commit at `rev`: one per table, in table order.
    pub(crate) fn events(&self, rev: Rev, tx: TxId) -> Vec<Event> {
        self.tables
            .iter()
            .map(|(kind, (ranges, ids))| Event {
                rev,
                tx,
                kind: *kind,
                ranges: ranges.clone(),
                ids: ids.iter().cloned().collect(),
            })
            .collect()
    }
}

impl Program {
    /// Gives the epochs.
    #[must_use]
    pub fn epochs(&self) -> &Epochs {
        &self.changes().epochs
    }

    /// Gives the epoch of a table: the revision of its last change.
    ///
    /// A table that merges the analysis layer has at least the epoch of the analysis table.
    #[must_use]
    pub fn epoch(&self, table: Table) -> Rev {
        let e = self.epochs();
        if table.merges_analysis() {
            e.table(table).max(e.table(Table::Analysis))
        } else {
            e.table(table)
        }
    }

    /// Gives the epoch of a function: the highest epoch of the facts that its views read.
    ///
    /// The module doc lists these facts. An unknown function gives the epoch of its record
    /// facts and of the analysis table.
    #[must_use]
    pub fn func_epoch(&self, func: FuncId) -> Rev {
        let e = self.epochs();
        let mut best = e.table(Table::Analysis).max(e.func(func));
        let Some(view) = self.func(func) else {
            return best;
        };
        best = best.max(e.in_ranges(&view.func.body));
        for range in view.func.body.ranges() {
            let units = self.analysis().listing().units_in(*range);
            for (off, _) in units.chain(self.base().listing().units_in(*range)) {
                for r in self.refs_from(Address::ram(off)) {
                    let kind = r.value.key.kind;
                    let jump =
                        matches!(kind, RefType::UnconditionalJump | RefType::ConditionalJump);
                    if kind.is_call() || jump {
                        best = best.max(e.func(FuncId(r.value.key.to)));
                    }
                }
            }
        }
        best
    }
}
