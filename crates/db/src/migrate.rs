//! The migration of the project files of format version 1 (design Section 3.10).
//!
//! Version 1 gave each import the EXTERNAL address of its place in the import list of the
//! binary model. Version 2 gives each import 1 plus the rank of its import ID. So a version 1
//! snapshot and a version 1 journal line can hold old `ext:` addresses.
//!
//! [`ExtMap`] maps the text of each old address to the text of its new address
//! ([`Program::v1_ext_map`]). [`ExtMap::remap`] changes each JSON string that is exactly an
//! old address. It changes all strings in one pass, so an old address never maps twice.
//! Other strings stay.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use ghidorah_base::Address;
use ghidorah_json::{Object, Value};

use crate::program::Program;

/// The map from the text of each version 1 `ext:` address to the text of its new address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtMap(BTreeMap<String, String>);

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
        Self(
            pairs
                .into_iter()
                .filter(|(old, new)| old != new)
                .map(|(old, new)| (old.to_string(), new.to_string()))
                .collect(),
        )
    }

    /// Tells if the map changes no address.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Gives `value` with each string that is an old address of the map replaced by its new
    /// address.
    #[must_use]
    pub fn remap(&self, value: Value) -> Value {
        match value {
            Value::String(s) => Value::String(self.0.get(&s).cloned().unwrap_or(s)),
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
}
