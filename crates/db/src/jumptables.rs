//! The jump-table manager (design Sections 3.4 and 7.8).
//!
//! The key is the address of the indirect jump. A record holds at most [`MAX_ENTRIES`]
//! targets in case order. A record without targets is an unresolved table.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::{Address, JumpTableId};

use crate::fact::{Fact, Invalid, Origin, WriteError, put};

/// The largest number of entries of one table.
pub const MAX_ENTRIES: usize = 1024;

/// How a table got its targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JtMethod {
    /// Method A: the backward slice and the interpreter.
    A,
    /// The agent override `func_edit set_jumptable`.
    Agent,
}

impl JtMethod {
    /// Gives the output name: `a` or `agent`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::Agent => "agent",
        }
    }
}

impl fmt::Display for JtMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One jump table.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JumpTable {
    /// The table base, when the method finds one.
    pub base: Option<Address>,
    /// The entry size in bytes: 4 or 8, or 0 for an agent table.
    pub entry_size: u8,
    /// The number of entries.
    pub count: u16,
    /// The case targets in case order.
    pub targets: Vec<Address>,
    /// The method.
    pub method: JtMethod,
    /// The table has its targets.
    pub resolved: bool,
}

/// The jump tables of one layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JumpTables {
    map: BTreeMap<Address, Fact<JumpTable>>,
}

impl JumpTables {
    /// Gives the number of tables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Tells if the layer has no table.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Gives the table of an indirect jump.
    #[must_use]
    pub fn get(&self, id: JumpTableId) -> Option<&Fact<JumpTable>> {
        self.map.get(&id.0)
    }

    /// Gives all tables in address order.
    pub fn iter(&self) -> impl Iterator<Item = (JumpTableId, &Fact<JumpTable>)> {
        self.map.iter().map(|(a, t)| (JumpTableId(*a), t))
    }

    /// Sets the table of an indirect jump by the write rule. `None` removes it. Gives the old
    /// fact.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_ENTRIES`] targets, or
    /// [`WriteError::Blocked`] with the current table.
    pub(crate) fn set(
        &mut self,
        id: JumpTableId,
        table: Option<JumpTable>,
        origin: &Origin,
    ) -> Result<Option<Fact<JumpTable>>, WriteError<JumpTable>> {
        if let Some(t) = &table
            && t.targets.len() > MAX_ENTRIES
        {
            return Err(Invalid::TooMany {
                count: t.targets.len(),
                max: MAX_ENTRIES,
            }
            .into());
        }
        put(&mut self.map, id.0, table, origin)
    }
}
