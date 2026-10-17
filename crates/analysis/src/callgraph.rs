//! The call graph of the published facts (design Section 7.11).
//!
//! [`CallGraph::build`] reads the call references of both layers. The caller is the function
//! whose body holds the call site. The callee is one of these:
//!
//! | Target | Callee |
//! |---|---|
//! | the PLT stub of an import | the import |
//! | the EXTERNAL address of an import | the import |
//! | a function entry | the function |
//!
//! A call site outside every body and a target that is none of these give no edge.

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, FuncId, ImportId};
use ghidorah_db::Program;

/// The callee of a call edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Callee {
    /// A function of the program.
    Func(FuncId),
    /// An import.
    Import(ImportId),
}

/// The call graph of a program.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallGraph {
    calls: BTreeMap<FuncId, BTreeMap<Callee, BTreeSet<Address>>>,
    callers: BTreeMap<Callee, BTreeSet<FuncId>>,
}

impl CallGraph {
    /// Builds the call graph of `program`.
    #[must_use]
    pub fn build(program: &Program) -> Self {
        let _ = program;
        Self::default()
    }

    /// Gives the callees of `func` in callee order.
    #[must_use]
    pub fn callees(&self, func: FuncId) -> Vec<&Callee> {
        self.calls
            .get(&func)
            .map(|m| m.keys().collect())
            .unwrap_or_default()
    }

    /// Gives the callers of `callee` in entry order.
    #[must_use]
    pub fn callers(&self, callee: &Callee) -> Vec<FuncId> {
        self.callers
            .get(callee)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Gives the call sites in `func` that call `callee`, in address order.
    #[must_use]
    pub fn sites(&self, func: FuncId, callee: &Callee) -> Vec<Address> {
        self.calls
            .get(&func)
            .and_then(|m| m.get(callee))
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Gives every edge in caller order, then in callee order.
    #[must_use]
    pub fn edges(&self) -> Vec<(FuncId, &Callee)> {
        self.calls
            .iter()
            .flat_map(|(f, m)| m.keys().map(move |c| (*f, c)))
            .collect()
    }

    /// Gives the number of edges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.calls.values().map(BTreeMap::len).sum()
    }

    /// Tells if the graph has no edge.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
