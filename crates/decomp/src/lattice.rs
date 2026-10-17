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
//! [`field`] gives the field name of an access `v + k` with `w` bits when `v` has the type
//! `T *`, `T` is a complete record and `T` has a field of `w` bits at offset `k`. The printer
//! then shows `v->field`.

use ghidorah_types::{DataModel, Tier0, TypeId, TypeStore};

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
        let _ = store;
        None
    }

    /// Gives the C text of a type, for example `struct sockaddr_in *`.
    #[must_use]
    pub fn text(&self, ty: Ty) -> Option<String> {
        let _ = ty;
        None
    }

    /// Gives the C declaration of `name` with a type, for example `char *s`.
    #[must_use]
    pub fn decl(&self, ty: Ty, name: &str) -> Option<String> {
        let _ = (ty, name);
        None
    }
}

/// Gives the type of each variable of `view`. Variable `i` has the type `out[i]`.
#[must_use]
pub fn infer(view: &View, env: &dyn PrintEnv, stores: &Stores<'_>) -> Vec<Option<Ty>> {
    let _ = (env, stores);
    vec![None; view.vars.len()]
}

/// Gives the name of the field at offset `off` with `bits` bits of the record that `ptr`
/// points to.
#[must_use]
pub fn field(stores: &Stores<'_>, ptr: Ty, off: u64, bits: u8) -> Option<String> {
    let _ = (stores, ptr, off, bits);
    None
}
