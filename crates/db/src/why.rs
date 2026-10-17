//! Why-records (design Section 3.4, ADR-0023).
//!
//! Every ANALYSIS fact has a [`Why`]: a rule code and the keys of its premises. The store
//! gives each record a creation order. A premise must have a lower order than its fact, so
//! the premise graph has no cycle (Section 3.11, invariant 6).
//!
//! The analysis crate owns the closed rule catalog and its doc lines. This module keeps the
//! code text: `R_` and upper case letters, digits and `_`, for example `R_FDE_START`.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use ghidorah_base::{Address, ExportId, FuncId, ImportId, JumpTableId, NoteId, StringId, VarId};

use crate::comments::CommentKind;
use crate::fact::Invalid;
use crate::refs::RefKey;
use crate::symbols::SymKey;

/// The longest rule code in bytes.
pub const MAX_RULE: usize = 64;

/// The largest number of premises of one record.
pub const MAX_PREMISES: usize = 64;

/// A rule code, for example `R_FDE_START`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleCode(String);

impl RuleCode {
    /// Makes a rule code.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::EmptyName`] when the text is not `R_` and 1 or more upper case
    /// letters, digits and `_`, and [`Invalid::TooLong`] above [`MAX_RULE`] bytes.
    pub fn new(text: &str) -> Result<Self, Invalid> {
        let body_ok = |b: u8| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_';
        match text.strip_prefix("R_") {
            Some(body) if !body.is_empty() && body.bytes().all(body_ok) => {}
            _ => return Err(Invalid::EmptyName),
        }
        if text.len() > MAX_RULE {
            return Err(Invalid::TooLong {
                len: text.len(),
                max: MAX_RULE,
            });
        }
        Ok(Self(text.to_string()))
    }

    /// Gives the code text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The key of a fact or of an input of the binary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactKey {
    /// The code unit at a RAM offset.
    CodeUnit(u64),
    /// The data definition at a RAM offset.
    Data(u64),
    /// A symbol.
    Symbol(Address, SymKey),
    /// A function.
    Func(FuncId),
    /// The signature of a function.
    Signature(FuncId),
    /// The noreturn flag of a function.
    Noreturn(FuncId),
    /// A reference.
    Ref(RefKey),
    /// A comment.
    Comment(Address, CommentKind),
    /// A jump table.
    JumpTable(JumpTableId),
    /// A flow override.
    FlowOverride(Address),
    /// A string.
    Str(StringId),
    /// A variable.
    Var(VarId),
    /// An import of the binary.
    Import(ImportId),
    /// An export of the binary.
    Export(ExportId),
    /// An entry point of the binary at a RAM offset.
    Entry(u64),
    /// The relocation at a RAM offset.
    Reloc(u64),
    /// The FDE whose PC range starts at a RAM offset.
    Fde(u64),
    /// A note.
    Note(NoteId),
}

/// The reason of a fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Why {
    /// The rule.
    pub rule: RuleCode,
    /// The premises, at most [`MAX_PREMISES`].
    pub premises: Vec<FactKey>,
}

/// The why-records of one layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WhyStore {
    map: BTreeMap<FactKey, (u64, Why)>,
    next: u64,
}

impl WhyStore {
    /// Gives the number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Tells if the layer has no record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Gives the record of a fact.
    #[must_use]
    pub fn get(&self, key: &FactKey) -> Option<&Why> {
        self.map.get(key).map(|(_, w)| w)
    }

    /// Gives the creation order of the record of a fact.
    #[must_use]
    pub fn order(&self, key: &FactKey) -> Option<u64> {
        self.map.get(key).map(|(o, _)| *o)
    }

    /// Gives all records in key order with their creation order.
    pub fn iter(&self) -> impl Iterator<Item = (&FactKey, u64, &Why)> {
        self.map.iter().map(|(k, (o, w))| (k, *o, w))
    }

    /// Sets the record of a fact. The record gets the next creation order. Gives the old record.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_PREMISES`] premises.
    pub(crate) fn insert(&mut self, key: FactKey, why: Why) -> Result<Option<Why>, Invalid> {
        if why.premises.len() > MAX_PREMISES {
            return Err(Invalid::TooMany {
                count: why.premises.len(),
                max: MAX_PREMISES,
            });
        }
        let order = self.next;
        self.next = self.next.saturating_add(1);
        Ok(self.map.insert(key, (order, why)).map(|(_, w)| w))
    }

    /// Removes the record of a fact and gives it.
    pub(crate) fn remove(&mut self, key: &FactKey) -> Option<Why> {
        self.map.remove(key).map(|(_, w)| w)
    }

    /// Gives the creation order of the next new record.
    #[must_use]
    pub const fn next_order(&self) -> u64 {
        self.next
    }

    /// Sets the record of a fact with its creation order. Gives the old record.
    ///
    /// The next order stays above `order`. The JSON codec uses this function for an exact copy.
    ///
    /// # Errors
    ///
    /// Returns [`Invalid::TooMany`] above [`MAX_PREMISES`] premises.
    pub(crate) fn insert_at(
        &mut self,
        key: FactKey,
        order: u64,
        why: Why,
    ) -> Result<Option<Why>, Invalid> {
        if why.premises.len() > MAX_PREMISES {
            return Err(Invalid::TooMany {
                count: why.premises.len(),
                max: MAX_PREMISES,
            });
        }
        self.next = self.next.max(order.saturating_add(1));
        Ok(self.map.insert(key, (order, why)).map(|(_, w)| w))
    }

    /// Sets the creation order of the next new record. The order never goes below a stored order.
    pub(crate) fn set_next(&mut self, next: u64) {
        self.next = self.next.max(next);
    }
}
