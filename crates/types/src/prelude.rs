//! The built-in prelude types (design Section 9.2).
//!
//! The prelude comes from the const table of `tables/prelude.rs`. It holds the `stdint.h`
//! names, `size_t` and the other POSIX typedefs, opaque types such as `FILE`, and the records
//! that Tier-0 uses: `struct sockaddr`, `struct sockaddr_in`, `struct in_addr` and
//! `struct timespec`. The C parser reads the type text of each item.

use std::fmt;

use crate::cparse::CParseError;
use crate::store::{StoreError, TypeStore};

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
        f.write_str("prelude error")
    }
}

impl std::error::Error for PreludeError {}

/// Adds the prelude types to `store`.
///
/// # Errors
///
/// Returns [`PreludeError`] for the first item that does not install.
pub fn install(store: &mut TypeStore) -> Result<(), PreludeError> {
    let _ = store;
    Err(PreludeError::Store {
        item: "",
        error: StoreError::Full,
    })
}

/// Gives the names of the prelude items: typedef names and tags.
pub fn names() -> impl Iterator<Item = &'static str> {
    std::iter::empty()
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
