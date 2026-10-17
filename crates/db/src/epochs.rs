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
//! - the record of each callee: a call reference from the body names it.
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

use ghidorah_base::{Address, FuncId, Rev};
use ghidorah_kernel::RangeSet;

use crate::edit::Edit;
use crate::program::Program;
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
        let _ = ranges;
        Rev(0)
    }

    /// Records the changes of one commit at `rev`.
    pub(crate) fn record(&mut self, rev: Rev, touch: &Touch) {
        let _ = (rev, touch);
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

impl Touch {
    /// Adds the changes of `edit`.
    pub(crate) fn add(&mut self, edit: &Edit) {
        let _ = edit;
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
        let _ = table;
        Rev(0)
    }

    /// Gives the epoch of a function: the highest epoch of the facts that its views read.
    ///
    /// The module doc lists these facts. An unknown function gives the epoch of its record
    /// facts and of the analysis table.
    #[must_use]
    pub fn func_epoch(&self, func: FuncId) -> Rev {
        let _ = func;
        Rev(0)
    }
}
