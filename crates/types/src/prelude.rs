//! The built-in prelude types (design Section 9.2).
//!
//! The prelude comes from the const table of `tables/prelude.rs`. It holds the `stdint.h`
//! names, `size_t` and the other POSIX typedefs, opaque types such as `FILE`, and the records
//! that Tier-0 uses: `struct sockaddr`, `struct sockaddr_in`, `struct in_addr` and
//! `struct timespec`. The C parser reads the type text of each item. A second install
//! changes nothing.

use std::fmt;

use crate::cparse::{CParseError, parse_type};
use crate::store::{StoreError, TypeStore};
use crate::tables::Item;
use crate::tables::prelude::PRELUDE;
use crate::ty::Field;

/// An error of the prelude install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreludeError {
    /// The type text of an item does not parse.
    Parse {
        /// The item name.
        item: &'static str,
        /// The parser error.
        error: CParseError,
    },
    /// The store rejects an item.
    Store {
        /// The item name.
        item: &'static str,
        /// The store error.
        error: StoreError,
    },
}

impl fmt::Display for PreludeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { item, error } => {
                write!(f, "The prelude item `{item}` does not parse: {error}")
            }
            Self::Store { item, error } => {
                write!(f, "The prelude item `{item}` does not install: {error}")
            }
        }
    }
}

impl std::error::Error for PreludeError {}

/// Parses the type text of the item `item`.
fn ty(
    store: &mut TypeStore,
    item: &'static str,
    text: &str,
) -> Result<crate::ty::TypeId, PreludeError> {
    parse_type(store, text).map_err(|error| PreludeError::Parse { item, error })
}

/// Adds the prelude types to `store`.
///
/// # Errors
///
/// Returns [`PreludeError`] for the first item that does not install.
pub fn install(store: &mut TypeStore) -> Result<(), PreludeError> {
    for item in PRELUDE {
        match *item {
            Item::Typedef(name, text) => {
                let target = ty(store, name, text)?;
                store
                    .typedef(name, target)
                    .map_err(|error| PreludeError::Store { item: name, error })?;
            }
            Item::Opaque(kind, tag) => {
                store
                    .declare(kind.into(), tag)
                    .map_err(|error| PreludeError::Store { item: tag, error })?;
            }
            Item::Record(kind, tag, fields) => {
                let mut list = Vec::with_capacity(fields.len());
                for (name, text) in fields {
                    list.push(Field::new(name, ty(store, tag, text)?));
                }
                store
                    .define_record(kind, Some(tag), list)
                    .map_err(|error| PreludeError::Store { item: tag, error })?;
            }
        }
    }
    Ok(())
}

/// Gives the names of the prelude items: typedef names and tags.
pub fn names() -> impl Iterator<Item = &'static str> {
    PRELUDE.iter().map(|item| match *item {
        Item::Typedef(name, _) | Item::Opaque(_, name) | Item::Record(_, name, _) => name,
    })
}

impl TypeStore {
    /// Makes a store with the primitive types and the prelude.
    ///
    /// # Errors
    ///
    /// Returns [`PreludeError`] when the prelude does not install.
    pub fn with_prelude() -> Result<Self, PreludeError> {
        let mut store = Self::new();
        install(&mut store)?;
        Ok(store)
    }
}
