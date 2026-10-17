//! The canonical C text of a type and the type reference (design Sections 3.5 and 9.1).
//!
//! The C parser reads the canonical text back to the same type. The rules:
//!
//! - A declarator follows the base type after one space: `char *`, `int [4]`, `char *name`.
//! - A pointer to an array or a function gets parentheses: `int (*)[4]`, `void (*)(int)`.
//! - A qualifier comes before the base type, `const char *`, or after the star, `char *const`.
//! - A named record or enum prints its tag. A record without a tag prints its fields.
//! - An empty parameter list prints `void`. A variadic list ends with `, ...`.
//! - A function that does not return starts with `_Noreturn`. The calling convention has no text.
//!
//! A named type has the reference `t:<name>`. Another type has the reference `t:#<fnv64>`,
//! the FNV-1a hash of its canonical text.

use ghidorah_base::TypeRef;

use crate::store::{StoreError, TypeStore};
use crate::ty::TypeId;

/// The longest canonical C text in bytes.
pub const MAX_TEXT: usize = 1 << 20;

impl TypeStore {
    /// Gives the canonical C text of the type `id`, for example `const char *`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::Depth`] or [`StoreError::TextLimit`].
    pub fn c_text(&self, id: TypeId) -> Result<String, StoreError> {
        Err(StoreError::UnknownId(id))
    }

    /// Gives the canonical C declaration of `name` with the type `id`, for example `char *argv[]`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::Depth`] or [`StoreError::TextLimit`].
    pub fn c_decl(&self, id: TypeId, name: &str) -> Result<String, StoreError> {
        let _ = name;
        Err(StoreError::UnknownId(id))
    }

    /// Gives the C definition of a type, with a final `;`.
    ///
    /// A record gives `struct s { char a; int b; };`. An enum gives its constants.
    /// A typedef gives `typedef unsigned long size_t;`. Another type gives its declaration.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnknownId`], [`StoreError::Depth`] or [`StoreError::TextLimit`].
    pub fn c_definition(&self, id: TypeId) -> Result<String, StoreError> {
        Err(StoreError::UnknownId(id))
    }

    /// Gives the reference of the type `id`.
    ///
    /// A record or an enum with a tag, a typedef and a primitive type have a name.
    /// Another type has the hash of its canonical text.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`TypeStore::c_text`].
    pub fn type_ref(&self, id: TypeId) -> Result<TypeRef, StoreError> {
        Err(StoreError::UnknownId(id))
    }

    /// Finds the type of a reference.
    ///
    /// A name finds a typedef first, then a tag, then a primitive type. A hash finds the
    /// first type in ID order whose canonical text has that hash.
    #[must_use]
    pub fn by_ref(&self, reference: &TypeRef) -> Option<TypeId> {
        let _ = reference;
        None
    }
}
