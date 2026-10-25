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

use ghidorah_base::{Address, FuncId};
use ghidorah_db::{FactKey, Program, Source, SymKind};

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
        match &self.key {
            FactKey::Func(f) => f.to_string(),
            FactKey::Var(v) => v.to_string(),
            FactKey::Ref(r) => r
                .id()
                .map_or_else(|_| self.at.to_string(), |id| id.to_string()),
            _ => self.at.to_string(),
        }
    }

    /// Tells if the fact lost its function, so `func_edit create` at [`Orphan::at`] puts it
    /// back.
    #[must_use]
    pub const fn lost_function(&self) -> bool {
        !matches!(self.kind, OrphanKind::Ref)
    }
}

/// Tells if a fact of `source` counts: an agent fact or a user fact.
const fn counts(source: Source) -> bool {
    matches!(source, Source::Agent | Source::User)
}

/// Gives the orphaned agent facts of `program` in key order.
///
/// Run it on a complete analysis. Between an edit and its re-analysis, the analysis layer
/// can lack a new agent function, so the function shows as an orphan.
#[must_use]
pub fn find(program: &Program) -> Vec<Orphan> {
    let base = program.base();
    let analysis = program.analysis();
    let lost = |entry: Address| analysis.func(FuncId(entry)).is_none();
    let mut out = Vec::new();
    for f in base.funcs().iter() {
        if counts(f.source) && lost(f.entry) {
            out.push(Orphan {
                key: FactKey::Func(f.id()),
                kind: OrphanKind::Function,
                at: f.entry,
                source: f.source,
            });
        }
    }
    for (var, facts) in base.vars().iter() {
        let source = facts
            .name
            .as_ref()
            .map(|n| n.source)
            .or_else(|| facts.ty.as_ref().map(|t| t.source));
        if let Some(source) = source.filter(|s| counts(*s))
            && lost(var.func.0)
        {
            out.push(Orphan {
                key: FactKey::Var(var.clone()),
                kind: OrphanKind::Var,
                at: var.func.0,
                source,
            });
        }
    }
    for s in base.symbols().iter() {
        if s.kind == SymKind::Function && counts(s.name.source) && lost(s.addr) {
            out.push(Orphan {
                key: FactKey::Symbol(s.addr, s.key),
                kind: OrphanKind::Name,
                at: s.addr,
                source: s.name.source,
            });
        }
    }
    for r in base.refs().iter() {
        let from = r.value.key.from;
        let code = from.is_ram()
            && (program.code_unit(from.off).is_some() || program.data_def(from.off).is_some());
        if counts(r.source) && !code {
            out.push(Orphan {
                key: FactKey::Ref(r.value.key),
                kind: OrphanKind::Ref,
                at: from,
                source: r.source,
            });
        }
    }
    out.sort();
    out
}
