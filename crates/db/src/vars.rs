//! The variable manager (design Section 3.4).
//!
//! The key is a [`VarId`]: a function and a storage. A variable has a name fact and a type
//! fact. Each fact follows the write rule on its own. A variable with no fact has no entry.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use ghidorah_base::id::MAX_NAME_LEN;
use ghidorah_base::{FuncId, VarId};
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
        let _ = func;
        std::iter::empty()
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
        let _ = (var, name, origin, MAX_NAME_LEN, put_slot::<String>);
        Err(Invalid::DefaultSource.into())
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
        let _ = (var, ty, origin);
        Err(Invalid::DefaultSource.into())
    }
}
