//! The type manager: the [`TypeStore`] of a program and its data model (design Sections 3.4
//! and 9).
//!
//! A program starts with the primitive types and the prelude. The binary format selects the
//! data model. ELF and raw binaries use `x86_64-sysv`. The PE work package adds the model
//! `x86_64-win` for PE32+ files.

#[cfg(test)]
mod tests;

use ghidorah_base::TypeRef;
use ghidorah_loader::Format;
use ghidorah_types::{DataModel, PreludeError, Proto, Sig, StoreError, Type, TypeId, TypeStore};

/// The types of one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Types {
    store: TypeStore,
    model: DataModel,
}

/// Gives the data model of a binary format.
#[must_use]
pub const fn model_for(format: Format) -> DataModel {
    match format {
        Format::Elf64Le | Format::Raw | Format::Pe32Plus => DataModel::X86_64_SYSV,
    }
}

impl Types {
    /// Makes the types of a binary of `format`: the primitive types and the prelude.
    ///
    /// # Errors
    ///
    /// Returns the [`PreludeError`] of the prelude install.
    pub fn for_format(format: Format) -> Result<Self, PreludeError> {
        Ok(Self {
            store: TypeStore::with_prelude()?,
            model: model_for(format),
        })
    }

    /// Gives the store.
    #[must_use]
    pub const fn store(&self) -> &TypeStore {
        &self.store
    }

    /// Gives the data model.
    #[must_use]
    pub const fn model(&self) -> &DataModel {
        &self.model
    }

    /// Gives the signature of a function type. Another type gives `None`.
    #[must_use]
    pub fn sig(&self, id: TypeId) -> Option<&Sig> {
        match self.store.get(id)? {
            Type::Func(sig) => Some(sig),
            _ => None,
        }
    }

    /// Gives the `t:` reference of a type.
    ///
    /// # Errors
    ///
    /// Returns the [`StoreError`] of an unknown ID or a text above the cap.
    pub fn type_ref(&self, id: TypeId) -> Result<TypeRef, StoreError> {
        self.store.type_ref(id)
    }

    /// Gives the type of a `t:` reference.
    #[must_use]
    pub fn by_ref(&self, reference: &TypeRef) -> Option<TypeId> {
        self.store.by_ref(reference)
    }

    /// Gives the Tier-0 prototype of a linked name. A version suffix after `@` does not count.
    #[must_use]
    pub fn prototype(name: &str) -> Option<&'static Proto> {
        ghidorah_types::proto::builtin().ok()?.get(name)
    }

    /// Gives the store for a change.
    pub(crate) const fn store_mut(&mut self) -> &mut TypeStore {
        &mut self.store
    }
}
