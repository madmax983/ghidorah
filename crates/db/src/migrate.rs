//! The migration of the project files of format version 1 (design Section 3.10).
//!
//! Version 1 gave each import the EXTERNAL address of its place in the import list of the
//! binary model. Version 2 gives each import 1 plus the rank of its import ID. So a version 1
//! snapshot and a version 1 journal line can hold old `ext:` addresses.
//!
//! [`ExtMap`] maps each old address to its new address ([`Program::v1_ext_map`]).
//! [`ExtMap::remap`] changes each JSON string that is exactly one address or one `ref:` ID in
//! canonical form. It changes all strings in one pass, so an old address never maps twice.
//! Other strings and the object member names stay.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use ghidorah_base::{Address, RefId};
use ghidorah_json::{Object, Value};

use crate::program::Program;

/// The map from each version 1 `ext:` address to its new address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtMap(BTreeMap<Address, Address>);

impl ExtMap {
    /// Gives the map of the imports of `program`. An address that does not change has no
    /// entry.
    #[must_use]
    pub fn of(program: &Program) -> Self {
        Self::from_pairs(program.v1_ext_map())
    }

    /// Gives the map of the pairs `(old, new)`. A pair with two equal addresses has no entry.
    #[must_use]
    pub fn from_pairs(pairs: impl IntoIterator<Item = (Address, Address)>) -> Self {
        Self(pairs.into_iter().filter(|(old, new)| old != new).collect())
    }

    /// Tells if the map changes no address.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Gives `value` with the old addresses of the map replaced by their new addresses (see
    /// the module doc).
    #[must_use]
    pub fn remap(&self, value: Value) -> Value {
        match value {
            Value::String(s) => Value::String(self.text(s)),
            Value::Array(items) => Value::Array(items.into_iter().map(|v| self.remap(v)).collect()),
            Value::Object(o) => {
                let mut out = Object::new();
                for (k, v) in o.into_members() {
                    out.push(k, self.remap(v));
                }
                Value::Object(out)
            }
            other => other,
        }
    }

    /// Gives the new address of `a`, or `a` when the map does not change it.
    fn address(&self, a: Address) -> Address {
        self.0.get(&a).copied().unwrap_or(a)
    }

    /// Gives the string `s` with its old addresses replaced, when it is one address or one
    /// `ref:` ID in canonical form. Else gives `s`.
    fn text(&self, s: String) -> String {
        if let Ok(a) = Address::parse(&s)
            && a.to_string() == s
        {
            return self.address(a).to_string();
        }
        if s.starts_with("ref:")
            && let Ok(r) = s.parse::<RefId>()
            && r.to_string() == s
            && let Ok(new) = RefId::new(self.address(r.from()), self.address(r.to()), r.kind())
        {
            return new.to_string();
        }
        s
    }
}
