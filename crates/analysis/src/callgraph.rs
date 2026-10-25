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
//!
//! A call to a PLT stub is an edge to the import, not to the stub function. So
//! [`CallGraph::callers_of_func`] merges the callers of the import into the callers of its
//! stub or thunk function ([`import_entry`]).

use std::collections::{BTreeMap, BTreeSet};

use ghidorah_base::{Address, FuncId, ImportId};
use ghidorah_db::{ImportRow, Program};

/// Gives the entry of the stub or thunk of an import. A PLT stub of the loader comes first.
/// Else the entry is the lowest function with the `thunk` flag that jumps through the slot.
#[must_use]
pub fn import_entry(program: &Program, row: &ImportRow) -> Option<Address> {
    if row.stub.is_some() {
        return row.stub;
    }
    program
        .refs_to(row.ext)
        .iter()
        .map(|r| r.value.key.from)
        .filter(|from| {
            program
                .func(FuncId(*from))
                .is_some_and(|f| f.func.flags.thunk)
        })
        .min()
}

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
    entries: BTreeMap<FuncId, BTreeSet<ImportId>>,
}

impl CallGraph {
    /// Builds the call graph of `program`.
    #[must_use]
    pub fn build(program: &Program) -> Self {
        let mut imports: BTreeMap<Address, &ImportId> = BTreeMap::new();
        for row in program.imports().values() {
            imports.insert(row.ext, &row.id);
            if let Some(stub) = row.stub {
                imports.insert(stub, &row.id);
            }
        }
        let mut out = Self::default();
        for row in program.imports().values() {
            let entry = import_entry(program, row).map(FuncId);
            if let Some(func) = entry.filter(|f| program.func(*f).is_some()) {
                out.entries.entry(func).or_default().insert(row.id.clone());
            }
        }
        for layer in program.layers() {
            for r in layer.refs().iter() {
                let key = r.value.key;
                if !key.kind.is_call() {
                    continue;
                }
                let Some(from) = program.owner_of(key.from) else {
                    continue;
                };
                let callee = if let Some(id) = imports.get(&key.to) {
                    Callee::Import((*id).clone())
                } else if program.func(FuncId(key.to)).is_some() {
                    Callee::Func(FuncId(key.to))
                } else {
                    continue;
                };
                out.callers.entry(callee.clone()).or_default().insert(from);
                out.calls
                    .entry(from)
                    .or_default()
                    .entry(callee)
                    .or_default()
                    .insert(key.from);
            }
        }
        out
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

    /// Gives the nodes that stand for the function `func`: the function, then each import
    /// whose stub or thunk it is.
    fn nodes_of(&self, func: FuncId) -> Vec<Callee> {
        let imports = self.entries.get(&func).into_iter().flatten();
        std::iter::once(Callee::Func(func))
            .chain(imports.cloned().map(Callee::Import))
            .collect()
    }

    /// Gives the callers of the function `func` in entry order. The callers of a stub or
    /// thunk include the callers of its import.
    #[must_use]
    pub fn callers_of_func(&self, func: FuncId) -> Vec<FuncId> {
        let mut out = BTreeSet::new();
        for node in self.nodes_of(func) {
            out.extend(self.callers.get(&node).into_iter().flatten().copied());
        }
        out.into_iter().collect()
    }

    /// Gives the call sites in `caller` that call the function `func` or the import of a
    /// stub or thunk `func`, in address order.
    #[must_use]
    pub fn sites_of_func(&self, caller: FuncId, func: FuncId) -> Vec<Address> {
        let mut out = BTreeSet::new();
        for node in self.nodes_of(func) {
            out.extend(self.sites(caller, &node));
        }
        out.into_iter().collect()
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
