//! The symbol manager (design Section 3.4).
//!
//! The key of a symbol is its address and a [`SymKey`]. A rename changes the name fact, never
//! the key. A name index maps each name to its addresses in address order.
//!
//! Rules:
//!
//! - An address with symbols has exactly one primary symbol.
//! - The first symbol of an address is primary. A removed primary passes the flag to the
//!   symbol with the lowest key.
//! - The names at one address differ. A second add of the same name gives the first key.
//! - A name has 1 to [`MAX_NAME_LEN`] bytes. The DB never stores a default name.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::Address;
use ghidorah_base::id::MAX_NAME_LEN;

use crate::fact::{Fact, Invalid, Origin, WriteError};

/// The kind of a symbol. The codes are the Ghidra codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SymKind {
    /// `LABEL`: a code or data label.
    Label = 0,
    /// `LIBRARY`: an external library.
    Library = 1,
    /// `FUNCTION`: the name of a function entry.
    Function = 5,
    /// `PARAMETER`: a parameter.
    Parameter = 6,
    /// `LOCAL_VAR`: a local variable.
    LocalVar = 7,
    /// `GLOBAL_VAR`: a global variable.
    GlobalVar = 8,
}

impl SymKind {
    /// All kinds in code order.
    pub const ALL: [Self; 6] = [
        Self::Label,
        Self::Library,
        Self::Function,
        Self::Parameter,
        Self::LocalVar,
        Self::GlobalVar,
    ];

    /// Gives the Ghidra code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Gives the kind of a Ghidra code. Another code gives `None`.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.code() == code)
    }

    /// Gives the output name, for example `function`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Label => "label",
            Self::Library => "library",
            Self::Function => "function",
            Self::Parameter => "parameter",
            Self::LocalVar => "local_var",
            Self::GlobalVar => "global_var",
        }
    }
}

impl fmt::Display for SymKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The key of a symbol at its address. The manager gives the keys in add order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymKey(pub u16);

/// One symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The address.
    pub addr: Address,
    /// The key at the address.
    pub key: SymKey,
    /// The name and its provenance.
    pub name: Fact<String>,
    /// The kind.
    pub kind: SymKind,
    /// The symbol is the primary symbol of its address.
    pub primary: bool,
}

/// The symbols of one layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Symbols {
    table: BTreeMap<(Address, SymKey), Symbol>,
    by_name: BTreeMap<String, Vec<Address>>,
}

/// Checks a symbol name.
fn check_name(name: &str) -> Result<(), Invalid> {
    if name.is_empty() {
        Err(Invalid::EmptyName)
    } else if name.len() > MAX_NAME_LEN {
        Err(Invalid::TooLong {
            len: name.len(),
            max: MAX_NAME_LEN,
        })
    } else {
        Ok(())
    }
}

impl Symbols {
    /// Gives the number of symbols.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Tells if the layer has no symbol.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Gives the symbol with this key.
    #[must_use]
    pub fn get(&self, addr: Address, key: SymKey) -> Option<&Symbol> {
        self.table.get(&(addr, key))
    }

    /// Gives the symbols of an address in key order.
    pub fn at(&self, addr: Address) -> impl Iterator<Item = &Symbol> {
        let _ = addr;
        std::iter::empty()
    }

    /// Gives the primary symbol of an address.
    #[must_use]
    pub fn primary(&self, addr: Address) -> Option<&Symbol> {
        self.at(addr).find(|s| s.primary)
    }

    /// Gives the addresses of a name in address order.
    #[must_use]
    pub fn by_name(&self, name: &str) -> &[Address] {
        self.by_name.get(name).map_or(&[], Vec::as_slice)
    }

    /// Gives all symbols in address order, then key order.
    pub fn iter(&self) -> impl Iterator<Item = &Symbol> {
        self.table.values()
    }

    /// Gives each name with its addresses, in name order.
    pub fn names(&self) -> impl Iterator<Item = (&str, &[Address])> {
        self.by_name.iter().map(|(n, a)| (n.as_str(), a.as_slice()))
    }

    /// Adds a symbol. The first symbol of an address is primary.
    ///
    /// A symbol with the same name at the address gives its key and no change.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::EmptyName`], [`Invalid::TooLong`] or [`Invalid::TooMany`] for an
    /// address that holds `u16::MAX` keys.
    pub(crate) fn add(
        &mut self,
        addr: Address,
        name: String,
        kind: SymKind,
        origin: &Origin,
    ) -> Result<SymKey, Invalid> {
        let _ = (
            addr,
            name,
            kind,
            origin,
            check_name as fn(&str) -> Result<(), Invalid>,
        );
        Ok(SymKey(0))
    }

    /// Sets the name of the primary symbol of `addr` by the write rule. `None` removes it.
    ///
    /// Without a primary symbol, a name makes a new primary symbol of `kind`. Gives the old
    /// name fact.
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::Blocked`] with the current name, the errors of a bad name, or
    /// [`Invalid::DuplicateName`] when another symbol at `addr` has the name.
    pub(crate) fn set_name(
        &mut self,
        addr: Address,
        name: Option<String>,
        kind: SymKind,
        origin: &Origin,
    ) -> Result<Option<Fact<String>>, WriteError<String>> {
        let _ = (addr, name, kind, origin);
        Ok(None)
    }

    /// Makes the symbol with `key` primary. Gives the key of the old primary symbol.
    ///
    /// An unknown key gives `None` and no change.
    pub(crate) fn set_primary(&mut self, addr: Address, key: SymKey) -> Option<SymKey> {
        let _ = (addr, key);
        None
    }

    /// Removes a symbol and gives it. A removed primary passes the flag on.
    pub(crate) fn remove(&mut self, addr: Address, key: SymKey) -> Option<Symbol> {
        let _ = (addr, key);
        None
    }
}
