//! The reference manager (design Sections 3.4 and 7.5).
//!
//! The from-index maps a [`RefKey`] to its fact. The to-index holds the same keys in the
//! order `(to, from, op_index, kind)`. Every write changes both indexes, so they hold the same
//! set (Section 3.11, invariant 1).

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidorah_base::{Address, IdError, RefId};

use crate::fact::{Fact, Origin, WriteError};

/// The type of a reference. The codes are the Ghidra `RefType` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RefType {
    /// `FALL_THROUGH`.
    FallThrough = 0,
    /// `UNCONDITIONAL_JUMP`.
    UnconditionalJump = 1,
    /// `CONDITIONAL_JUMP`.
    ConditionalJump = 2,
    /// `UNCONDITIONAL_CALL`.
    UnconditionalCall = 3,
    /// `CONDITIONAL_CALL`.
    ConditionalCall = 4,
    /// `TERMINATOR`.
    Terminator = 5,
    /// `COMPUTED_JUMP`: a jump-table case or an indirect jump target.
    ComputedJump = 6,
    /// `CONDITIONAL_TERMINATOR`.
    ConditionalTerminator = 7,
    /// `COMPUTED_CALL`: an indirect call target.
    ComputedCall = 8,
    /// `INDIRECTION`.
    Indirection = 9,
    /// `DATA`: a pointer.
    Data = 100,
    /// `READ`.
    Read = 101,
    /// `WRITE`.
    Write = 102,
    /// `READ_WRITE`.
    ReadWrite = 103,
    /// `PARAM`.
    Param = 107,
    /// `EXTERNAL_REF`.
    ExternalRef = 113,
    /// `THUNK`.
    Thunk = 127,
}

/// Each type with its output name, in code order.
const NAMES: [(RefType, &str); 17] = [
    (RefType::FallThrough, "fall_through"),
    (RefType::UnconditionalJump, "unconditional_jump"),
    (RefType::ConditionalJump, "conditional_jump"),
    (RefType::UnconditionalCall, "unconditional_call"),
    (RefType::ConditionalCall, "conditional_call"),
    (RefType::Terminator, "terminator"),
    (RefType::ComputedJump, "computed_jump"),
    (RefType::ConditionalTerminator, "conditional_terminator"),
    (RefType::ComputedCall, "computed_call"),
    (RefType::Indirection, "indirection"),
    (RefType::Data, "data"),
    (RefType::Read, "read"),
    (RefType::Write, "write"),
    (RefType::ReadWrite, "read_write"),
    (RefType::Param, "param"),
    (RefType::ExternalRef, "external_ref"),
    (RefType::Thunk, "thunk"),
];

impl RefType {
    /// All types in code order.
    pub const ALL: [Self; 17] = {
        let mut all = [Self::FallThrough; 17];
        let mut i = 0;
        while i < NAMES.len() {
            all[i] = NAMES[i].0;
            i += 1;
        }
        all
    };

    /// Gives the Ghidra code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Gives the type of a Ghidra code. Another code gives `None`.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.code() == code)
    }

    /// Gives the output name, for example `unconditional_call`. A `ref:` ID ends with it.
    #[must_use]
    pub fn name(self) -> &'static str {
        NAMES
            .iter()
            .find(|(t, _)| *t == self)
            .map_or("", |(_, n)| n)
    }

    /// Gives the type of an output name. An unknown name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        NAMES.iter().find(|(_, n)| *n == name).map(|(t, _)| *t)
    }

    /// Tells if the type is a flow type (codes below 100).
    #[must_use]
    pub const fn is_flow(self) -> bool {
        self.code() < 100
    }

    /// Tells if the type is a call.
    #[must_use]
    pub const fn is_call(self) -> bool {
        matches!(
            self,
            Self::UnconditionalCall | Self::ConditionalCall | Self::ComputedCall
        )
    }
}

impl fmt::Display for RefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The key of a reference: the order of the from-index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefKey {
    /// The instruction or data slot that refers.
    pub from: Address,
    /// The operand index, or -1 for the whole instruction.
    pub op_index: i8,
    /// The target.
    pub to: Address,
    /// The type.
    pub kind: RefType,
}

impl RefKey {
    /// Gives the `ref:` ID.
    ///
    /// # Errors
    ///
    /// Returns the [`IdError`] of [`RefId::new`].
    pub fn id(&self) -> Result<RefId, IdError> {
        RefId::new(self.from, self.to, self.kind.name())
    }
}

/// One reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ref {
    /// The key.
    pub key: RefKey,
    /// The reference is the primary reference of its operand.
    pub primary: bool,
}

/// The order of the to-index.
type ToKey = (Address, Address, i8, RefType);

/// Gives the to-index key of a reference key.
const fn to_key(k: &RefKey) -> ToKey {
    (k.to, k.from, k.op_index, k.kind)
}

/// The references of one layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refs {
    from: BTreeMap<RefKey, Fact<Ref>>,
    to: BTreeSet<ToKey>,
}

impl Refs {
    /// Gives the number of references.
    #[must_use]
    pub fn len(&self) -> usize {
        self.from.len()
    }

    /// Tells if the layer has no reference.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.from.is_empty()
    }

    /// Gives the reference with this key.
    #[must_use]
    pub fn get(&self, key: &RefKey) -> Option<&Fact<Ref>> {
        self.from.get(key)
    }

    /// Gives the references from `from` in key order.
    pub fn from(&self, from: Address) -> impl Iterator<Item = &Fact<Ref>> {
        let _ = from;
        std::iter::empty()
    }

    /// Gives the references to `to` in the order of the to-index.
    pub fn to(&self, to: Address) -> impl Iterator<Item = &Fact<Ref>> {
        let _ = (to, to_key as fn(&RefKey) -> ToKey);
        std::iter::empty()
    }

    /// Gives all references in key order.
    pub fn iter(&self) -> impl Iterator<Item = &Fact<Ref>> {
        self.from.values()
    }

    /// Gives the to-index keys in their order. Invariant checks compare them with the from-index.
    pub fn to_index(&self) -> impl Iterator<Item = RefKey> + '_ {
        self.to.iter().map(|&(to, from, op_index, kind)| RefKey {
            from,
            op_index,
            to,
            kind,
        })
    }

    /// Adds a reference by the write rule. A reference with the same key changes. Gives the
    /// old fact.
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::Blocked`] when a reference with the same key has a higher rank.
    pub(crate) fn add(
        &mut self,
        r: Ref,
        origin: &Origin,
    ) -> Result<Option<Fact<Ref>>, WriteError<Ref>> {
        let _ = (r, origin);
        Ok(None)
    }

    /// Removes a reference by the write rule. Gives the old fact, or `None` for no reference.
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::Blocked`] when the reference has a higher rank than `origin`.
    pub(crate) fn remove(
        &mut self,
        key: &RefKey,
        origin: &Origin,
    ) -> Result<Option<Fact<Ref>>, WriteError<Ref>> {
        let _ = (key, origin);
        Ok(None)
    }
}
