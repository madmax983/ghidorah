//! The minimal type lattice (design Section 8.4).
//!
//! A variable gets a type from a seed, then from one forward pass over the copies:
//!
//! | Seed | Type |
//! |---|---|
//! | an agent type on the `var:` ID | the type of the fact. It always wins. |
//! | a parameter of the function signature | the type of the parameter |
//! | a variable that is an argument of a call | the parameter type of the callee signature or prototype |
//! | the result of a call | the return type of the callee |
//!
//! The pass spreads a type over each copy `d = s` in statement order. Two different types
//! for one variable are a conflict, and the variable gets no type.
//!
//! [`field`] gives the field name of an access `v + k` with `w` bits. The type of `v` must be
//! `T *`, and the complete record `T` must have a field of `w` bits at offset `k`. The
//! printer then shows `v->field`.

use std::collections::BTreeSet;

use ghidorah_analysis::cc::loc_of;
use ghidorah_base::Storage;
use ghidorah_ir::Loc;
use ghidorah_types::{DataModel, Tier0, Type, TypeId, TypeStore, layout};

use crate::expr::{Call, Callee, Expr, Stmt, VarIdx};
use crate::print::PrintEnv;
use crate::view::View;

/// The store of a lattice type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Store {
    /// The type store of the program: agent types and signatures.
    Program,
    /// The type store of the Tier-0 prototypes.
    Tier0,
}

/// A type of the lattice: a store and an ID in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ty {
    /// The store.
    pub store: Store,
    /// The ID in the store.
    pub id: TypeId,
}

/// The stores that the lattice reads.
#[derive(Debug, Clone, Copy)]
pub struct Stores<'a> {
    /// The type store and the data model of the program, when the printer has a program.
    pub program: Option<(&'a TypeStore, &'a DataModel)>,
    /// The Tier-0 prototypes.
    pub tier0: Option<&'a Tier0>,
}

impl Stores<'_> {
    /// Gives the store of `store`.
    #[must_use]
    pub fn get(&self, store: Store) -> Option<&TypeStore> {
        match store {
            Store::Program => self.program.map(|p| p.0),
            Store::Tier0 => self.tier0.map(Tier0::store),
        }
    }

    /// Gives the data model of the layouts.
    fn model(&self) -> DataModel {
        self.program.map_or(DataModel::X86_64_SYSV, |p| *p.1)
    }

    /// Gives the C text of a type, for example `struct sockaddr_in *`.
    #[must_use]
    pub fn text(&self, ty: Ty) -> Option<String> {
        self.get(ty.store)?.c_text(ty.id).ok()
    }

    /// Gives the C declaration of `name` with a type, for example `char *s`.
    #[must_use]
    pub fn decl(&self, ty: Ty, name: &str) -> Option<String> {
        self.get(ty.store)?.c_decl(ty.id, name).ok()
    }

    /// Gives the type behind the typedefs and qualifiers of `ty`.
    fn resolved(&self, ty: Ty) -> Option<(&TypeStore, &Type)> {
        let store = self.get(ty.store)?;
        let id = store.resolve(ty.id).ok()?;
        Some((store, store.get(id)?))
    }

    /// Tells if `ty` is a signed integer type of `bits` bits.
    #[must_use]
    pub fn is_signed(&self, ty: Ty, bits: u8) -> bool {
        let Some((_, Type::Prim(p))) = self.resolved(ty) else {
            return false;
        };
        let model = self.model();
        let signed = p.is_integer() && model.is_signed(*p);
        signed
            && model
                .prim(*p)
                .is_some_and(|s| s.size.saturating_mul(8) == u64::from(bits))
    }
}

/// The candidate types of each variable during the pass.
struct Seeds {
    fixed: Vec<Option<Ty>>,
    seen: Vec<BTreeSet<Ty>>,
}

impl Seeds {
    fn add(&mut self, v: VarIdx, ty: Ty) {
        if let Some(set) = self.seen.get_mut(v.index()) {
            set.insert(ty);
        }
    }

    /// Gives the type of a variable now: the agent type, or the one candidate.
    fn current(&self, v: VarIdx) -> Option<Ty> {
        if let Some(t) = self.fixed.get(v.index()).copied().flatten() {
            return Some(t);
        }
        let set = self.seen.get(v.index())?;
        (set.len() == 1).then(|| set.first().copied()).flatten()
    }
}

/// Adds the seeds of one call: its argument variables and its result variable.
fn call_seeds(call: &Call, env: &dyn PrintEnv, seeds: &mut Seeds) {
    let Callee::Direct(target) = call.callee else {
        return;
    };
    let Some(sig) = env.signature(target) else {
        return;
    };
    let conv = env.conv();
    for (i, ty) in sig.params.iter().enumerate() {
        let Some(loc) = conv.int_args.get(i).and_then(|n| loc_of(n)) else {
            break;
        };
        if let Some((_, Expr::Var { var, .. })) = call.args.iter().find(|(l, _)| *l == loc) {
            seeds.add(*var, *ty);
        }
    }
    if let Some(ret) = sig.ret
        && let Some((_, v)) = call.rets.iter().find(|(l, _)| *l == Loc::RAX)
    {
        seeds.add(*v, ret);
    }
}

/// Gives the calls of a statement: the call statement and the calls in its expressions.
fn calls_of(s: &Stmt) -> Vec<&Call> {
    let mut out = Vec::new();
    if let Stmt::Call(c) = s {
        out.push(c);
    }
    for e in s.exprs() {
        for x in e.preorder() {
            if let Expr::Call(c) = x {
                out.push(c);
            }
        }
    }
    out
}

/// Gives the type of each variable of `view`. Variable `i` has the type `out[i]`.
#[must_use]
pub fn infer(view: &View, env: &dyn PrintEnv, stores: &Stores<'_>) -> Vec<Option<Ty>> {
    let n = view.vars.len();
    let mut seeds = Seeds {
        fixed: vec![None; n],
        seen: vec![BTreeSet::new(); n],
    };
    let program = stores.program.is_some();
    for (i, v) in view.vars.iter().enumerate() {
        if program
            && let Some(id) = env.var_type(&v.id)
            && let Some(slot) = seeds.fixed.get_mut(i)
        {
            *slot = Some(Ty {
                store: Store::Program,
                id,
            });
        }
    }
    if let Some(sig) = env.signature(view.entry) {
        for (i, v) in view.vars.iter().enumerate() {
            if let Storage::Param(p) = v.id.storage
                && let Some(ty) = sig.params.get(usize::from(p))
            {
                seeds.add(VarIdx(u32::try_from(i).unwrap_or(u32::MAX)), *ty);
            }
        }
    }
    let stmts: Vec<&Stmt> = view.nodes.iter().flat_map(|n| &n.stmts).collect();
    for s in &stmts {
        for c in calls_of(s) {
            call_seeds(c, env, &mut seeds);
        }
    }
    for s in &stmts {
        if let Stmt::Assign {
            var,
            value: Expr::Var { var: src, .. },
            ..
        } = s
            && let Some(ty) = seeds.current(*src)
        {
            seeds.add(*var, ty);
        }
    }
    (0..n)
        .map(|i| seeds.current(VarIdx(u32::try_from(i).unwrap_or(u32::MAX))))
        .collect()
}

/// Gives the name of the field at offset `off` with `bits` bits of the record that `ptr`
/// points to.
#[must_use]
pub fn field(stores: &Stores<'_>, ptr: Ty, off: u64, bits: u8) -> Option<String> {
    let (store, Type::Ptr(inner)) = stores.resolved(ptr)? else {
        return None;
    };
    let rec = store.resolve(*inner).ok()?;
    if !matches!(store.get(rec), Some(Type::Record(r)) if r.complete) {
        return None;
    }
    let found = layout::sysv(store, rec, &stores.model()).ok()?;
    found
        .fields
        .iter()
        .find(|f| f.offset == off && f.size.checked_mul(8) == Some(u64::from(bits)))
        .map(|f| f.name.clone())
}
