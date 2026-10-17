//! The variable manager (design Section 3.4).
//!
//! The key is a [`VarId`]: a function and a storage. A variable has a name fact and a type
//! fact. Each fact follows the write rule on its own. A variable with no fact has no entry.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use ghidorah_base::id::MAX_NAME_LEN;
use ghidorah_base::{FuncId, Storage, VarId};
use ghidorah_types::TypeId;

use crate::fact::{Fact, Invalid, Origin, WriteError, put_slot};

/// The facts of one variable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VarFact {
    /// The name fact.
    pub name: Option<Fact<String>>,
    /// The type fact.
    pub ty: Option<Fact<TypeId>>,
}

/// The variables of one layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vars {
    map: BTreeMap<VarId, VarFact>,
}

impl Vars {
    /// Gives the number of variables with a fact.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Tells if the layer has no variable fact.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Gives the facts of a variable.
    #[must_use]
    pub fn get(&self, var: &VarId) -> Option<&VarFact> {
        self.map.get(var)
    }

    /// Gives the variables of a function in storage order.
    pub fn of_func(&self, func: FuncId) -> impl Iterator<Item = (&VarId, &VarFact)> {
        let first = VarId {
            func,
            storage: Storage::Param(0),
        };
        self.map
            .range(first..)
            .take_while(move |(id, _)| id.func == func)
    }

    /// Writes one fact of `var` with `write`. A variable with no fact left loses its entry.
    fn change<T>(
        &mut self,
        var: &VarId,
        write: impl FnOnce(&mut VarFact) -> Result<Option<Fact<T>>, WriteError<T>>,
    ) -> Result<Option<Fact<T>>, WriteError<T>> {
        let mut facts = self.map.remove(var).unwrap_or_default();
        let result = write(&mut facts);
        if facts.name.is_some() || facts.ty.is_some() {
            self.map.insert(var.clone(), facts);
        }
        result
    }

    /// Gives all variables in ID order.
    pub fn iter(&self) -> impl Iterator<Item = (&VarId, &VarFact)> {
        self.map.iter()
    }

    /// Sets the name fact by the write rule. `None` removes it. Gives the old fact.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::EmptyName`], [`Invalid::TooLong`] or [`WriteError::Blocked`].
    pub(crate) fn set_name(
        &mut self,
        var: &VarId,
        name: Option<String>,
        origin: &Origin,
    ) -> Result<Option<Fact<String>>, WriteError<String>> {
        if let Some(n) = &name {
            if n.is_empty() {
                return Err(Invalid::EmptyName.into());
            }
            if n.len() > MAX_NAME_LEN {
                return Err(Invalid::TooLong {
                    len: n.len(),
                    max: MAX_NAME_LEN,
                }
                .into());
            }
        }
        self.change(var, |f| put_slot(&mut f.name, name, origin))
    }

    /// Sets the type fact by the write rule. `None` removes it. Gives the old fact.
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::Blocked`] with the current type.
    pub(crate) fn set_type(
        &mut self,
        var: &VarId,
        ty: Option<TypeId>,
        origin: &Origin,
    ) -> Result<Option<Fact<TypeId>>, WriteError<TypeId>> {
        self.change(var, |f| put_slot(&mut f.ty, ty, origin))
    }
}
