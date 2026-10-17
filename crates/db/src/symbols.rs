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
use std::ops::RangeInclusive;

use ghidorah_base::Address;
use ghidorah_base::id::MAX_NAME_LEN;

use crate::fact::{Fact, Invalid, Origin, WriteError, check};
use crate::source::Source;

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

/// Gives the key range of the symbols of `addr`.
const fn span(addr: Address) -> RangeInclusive<(Address, SymKey)> {
    (addr, SymKey(0))..=(addr, SymKey(u16::MAX))
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
        self.table.range(span(addr)).map(|(_, s)| s)
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

    /// Tells if a symbol at `addr` has the name `name`. The name index answers in log time.
    fn has_name(&self, addr: Address, name: &str) -> bool {
        self.by_name(name).binary_search(&addr).is_ok()
    }

    /// Adds `addr` to the index entry of `name`.
    fn index_add(&mut self, name: &str, addr: Address) {
        let list = self.by_name.entry(name.to_string()).or_default();
        if let Err(at) = list.binary_search(&addr) {
            list.insert(at, addr);
        }
    }

    /// Removes `addr` from the index entry of `name`. An empty entry goes.
    fn index_remove(&mut self, name: &str, addr: Address) {
        if let Some(list) = self.by_name.get_mut(name) {
            if let Ok(at) = list.binary_search(&addr) {
                list.remove(at);
            }
            if list.is_empty() {
                self.by_name.remove(name);
            }
        }
    }

    /// Adds a symbol. The first symbol of an address is primary.
    ///
    /// A symbol with the same name at the address gives its key and no change.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::DefaultSource`], [`Invalid::EmptyName`], [`Invalid::TooLong`] or
    /// [`Invalid::TooMany`] for an address whose last key is `u16::MAX`.
    pub(crate) fn add(
        &mut self,
        addr: Address,
        name: String,
        kind: SymKind,
        origin: &Origin,
    ) -> Result<SymKey, Invalid> {
        if origin.source == Source::Default {
            return Err(Invalid::DefaultSource);
        }
        check_name(&name)?;
        if self.has_name(addr, &name)
            && let Some(same) = self.at(addr).find(|s| s.name.value == name)
        {
            return Ok(same.key);
        }
        let last = self
            .table
            .range(span(addr))
            .next_back()
            .map(|(_, s)| s.key.0);
        let key = match last {
            None => SymKey(0),
            Some(k) => SymKey(k.checked_add(1).ok_or_else(|| Invalid::TooMany {
                count: usize::from(u16::MAX) + 1,
                max: usize::from(u16::MAX),
            })?),
        };
        self.index_add(&name, addr);
        let symbol = Symbol {
            addr,
            key,
            name: origin.fact(name),
            kind,
            primary: last.is_none(),
        };
        self.table.insert((addr, key), symbol);
        Ok(key)
    }

    /// Sets the name of the primary symbol of `addr` by the write rule. `None` removes it.
    ///
    /// Without a primary symbol, a name makes a new primary symbol of `kind`. A rename keeps
    /// the kind and the key. Gives the old name fact.
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
        let current = self.primary(addr).map(|s| (s.key, s.name.clone()));
        let Some((key, current)) = current else {
            check::<String>(None, origin)?;
            if let Some(name) = name {
                self.add(addr, name, kind, origin)?;
            }
            return Ok(None);
        };
        check(Some(&current), origin)?;
        let Some(name) = name else {
            return Ok(self.remove(addr, key).map(|s| s.name));
        };
        check_name(&name)?;
        if name != current.value && self.has_name(addr, &name) {
            return Err(Invalid::DuplicateName(name).into());
        }
        self.index_remove(&current.value, addr);
        self.index_add(&name, addr);
        Ok(self
            .table
            .get_mut(&(addr, key))
            .map(|s| std::mem::replace(&mut s.name, origin.fact(name))))
    }

    /// Makes the symbol with `key` primary. Gives the key of the old primary symbol.
    ///
    /// An unknown key gives `None` and no change.
    pub(crate) fn set_primary(&mut self, addr: Address, key: SymKey) -> Option<SymKey> {
        if !self.table.contains_key(&(addr, key)) {
            return None;
        }
        let old = self.primary(addr).map(|s| s.key);
        for s in self.table.range_mut(span(addr)).map(|(_, s)| s) {
            s.primary = s.key == key;
        }
        old
    }

    /// Removes a symbol and gives it. A removed primary passes the flag on.
    pub(crate) fn remove(&mut self, addr: Address, key: SymKey) -> Option<Symbol> {
        let symbol = self.table.remove(&(addr, key))?;
        self.index_remove(&symbol.name.value, addr);
        if symbol.primary
            && let Some((_, next)) = self.table.range_mut(span(addr)).next()
        {
            next.primary = true;
        }
        Some(symbol)
    }
}
