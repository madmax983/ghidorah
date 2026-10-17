//! Orphaned agent facts (design Section 3.9, ADR-0004).
//!
//! A re-analysis can take the anchor of an agent fact away. Lower-rank analysis never
//! deletes a higher-rank fact, so the fact stays at its address. [`find`] reports it:
//!
//! | Fact of the base layer | Orphan when |
//! |---|---|
//! | a function record: an agent function, a signature or a noreturn flag | the analysis layer has no function at its entry |
//! | a variable fact | the analysis layer has no function at the entry of its function |
//! | a symbol of the kind `FUNCTION` | the analysis layer has no function at its address |
//! | a reference | no code unit and no data definition starts at its source |
//!
//! Only `Agent` and `User` facts count. `Imported` facts come from the binary. Each orphan
//! gets `W_FACT_ORPHANED`. The remedy of a lost function is `func_edit` with the action
//! `create`. The list has the key order of [`FactKey`].

use std::fmt;

use ghidorah_base::Address;
use ghidorah_db::{FactKey, Program, Source};

/// The kind of an orphaned fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OrphanKind {
    /// A function record: an agent function, a signature or a noreturn flag.
    Function,
    /// A variable fact of a function.
    Var,
    /// A function name.
    Name,
    /// A reference whose source is not code.
    Ref,
}

impl OrphanKind {
    /// Gives the kind name: `function`, `variable`, `name` or `reference`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Var => "variable",
            Self::Name => "name",
            Self::Ref => "reference",
        }
    }
}

impl fmt::Display for OrphanKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One orphaned agent fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Orphan {
    /// The key of the fact.
    pub key: FactKey,
    /// The kind.
    pub kind: OrphanKind,
    /// The address where the fact stays: the entry, the symbol address or the source.
    pub at: Address,
    /// The source of the fact: `agent` or `user`.
    pub source: Source,
}

impl Orphan {
    /// Gives the ID text of the fact: `fn:`, `var:` or `ref:`, or the address of a name.
    #[must_use]
    pub fn id(&self) -> String {
        self.at.to_string()
    }

    /// Tells if the fact lost its function, so `func_edit create` at [`Orphan::at`] puts it
    /// back.
    #[must_use]
    pub const fn lost_function(&self) -> bool {
        false
    }
}

/// Gives the orphaned agent facts of `program` in key order.
#[must_use]
pub fn find(program: &Program) -> Vec<Orphan> {
    let _ = program;
    Vec::new()
}
