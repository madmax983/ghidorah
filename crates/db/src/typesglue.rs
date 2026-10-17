//! The type manager: the [`TypeStore`] of a program and its data model (design Sections 3.4
//! and 9).
//!
//! A program starts with the primitive types and the prelude. The binary format selects the
//! data model. ELF and raw binaries use `x86_64-sysv`. The PE work package adds the model
//! `x86_64-win` for PE32+ files.
//!
//! The store only grows. A transaction adds types with [`Tx::parse_sig`](crate::Tx::parse_sig)
//! and [`Tx::parse_type`](crate::Tx::parse_type). Each C text that adds a type is a
//! [`TypeInput`]. The journal line of the commit and the snapshot keep the inputs in order.
//! The parser is deterministic, so a replay of the inputs over the prelude gives the same
//! type IDs again.
//!
//! | Step | Store |
//! |---|---|
//! | a parse in a transaction | the new types, and the input when the store grows |
//! | a rollback or a commit with no edit | the store before the transaction |
//! | a commit with edits | the journal line holds the inputs of the transaction |
//! | a replay or a snapshot restore | the inputs parse again in order |
//! | an undo | the types stay. A type is a value, not a fact. |

#[cfg(test)]
mod tests;

use std::fmt;

use ghidorah_base::TypeRef;
use ghidorah_loader::Format;
use ghidorah_types::{
    CParseError, DataModel, ParsedSig, PreludeError, Proto, Sig, StoreError, Type, TypeId,
    TypeStore,
};

/// The parse mode of a [`TypeInput`] (design Section 9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypeMode {
    /// One prototype: `sig` mode.
    Sig,
    /// One abstract type: `type` mode.
    Type,
}

impl TypeMode {
    /// Gives the mode name: `sig` or `type`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sig => "sig",
            Self::Type => "type",
        }
    }

    /// Gives the mode of a name. Another name gives `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Sig, Self::Type]
            .into_iter()
            .find(|m| m.name() == name)
    }
}

/// One C text that added types to the store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeInput {
    /// The parse mode.
    pub mode: TypeMode,
    /// The C text.
    pub text: String,
}

/// The error of a replay of type inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputError {
    /// The index of the input that does not parse, from 0.
    pub index: usize,
    /// The parse error.
    pub error: CParseError,
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The type input {} does not parse: {}",
            self.index, self.error
        )
    }
}

impl std::error::Error for InputError {}

/// The types of one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Types {
    store: TypeStore,
    model: DataModel,
    inputs: Vec<TypeInput>,
}

/// Gives the data model of a binary format.
#[must_use]
pub const fn model_for(format: Format) -> DataModel {
    match format {
        Format::Elf64Le | Format::Raw | Format::Pe32Plus => DataModel::X86_64_SYSV,
    }
}

impl Types {
    /// Makes the types of a binary of `format`: the primitive types and the prelude.
    ///
    /// # Errors
    ///
    /// Returns the [`PreludeError`] of the prelude install.
    pub fn for_format(format: Format) -> Result<Self, PreludeError> {
        Ok(Self {
            store: TypeStore::with_prelude()?,
            model: model_for(format),
            inputs: Vec::new(),
        })
    }

    /// Gives the inputs that added types after the prelude, in parse order.
    #[must_use]
    pub fn inputs(&self) -> &[TypeInput] {
        &self.inputs
    }

    /// Parses the prototype `text` in `sig` mode into the store. A text that adds a type joins
    /// [`Types::inputs`].
    ///
    /// # Errors
    ///
    /// Returns the [`CParseError`] of the text. Then the store does not change.
    pub(crate) fn parse_sig(&mut self, text: &str) -> Result<ParsedSig, CParseError> {
        ghidorah_types::parse_sig(&mut self.store, text)
    }

    /// Parses the abstract type `text` in `type` mode into the store. A text that adds a type
    /// joins [`Types::inputs`].
    ///
    /// # Errors
    ///
    /// Returns the [`CParseError`] of the text. Then the store does not change.
    pub(crate) fn parse_type(&mut self, text: &str) -> Result<TypeId, CParseError> {
        ghidorah_types::parse_type(&mut self.store, text)
    }

    /// Parses `input` into the store in its mode.
    ///
    /// # Errors
    ///
    /// Returns the [`CParseError`] of the text. Then the store does not change.
    fn parse(&mut self, input: &TypeInput) -> Result<(), CParseError> {
        match input.mode {
            TypeMode::Sig => self.parse_sig(&input.text).map(drop),
            TypeMode::Type => self.parse_type(&input.text).map(drop),
        }
    }

    /// Parses each input of `inputs` in order in its mode.
    ///
    /// # Errors
    ///
    /// Returns the [`InputError`] of the first input that does not parse. The inputs before
    /// it stay.
    pub(crate) fn replay(&mut self, inputs: &[TypeInput]) -> Result<(), InputError> {
        for (index, input) in inputs.iter().enumerate() {
            self.parse(input)
                .map_err(|error| InputError { index, error })?;
        }
        Ok(())
    }

    /// Gives the store.
    #[must_use]
    pub const fn store(&self) -> &TypeStore {
        &self.store
    }

    /// Gives the data model.
    #[must_use]
    pub const fn model(&self) -> &DataModel {
        &self.model
    }

    /// Gives the signature of a function type. Another type gives `None`.
    #[must_use]
    pub fn sig(&self, id: TypeId) -> Option<&Sig> {
        match self.store.get(id)? {
            Type::Func(sig) => Some(sig),
            _ => None,
        }
    }

    /// Gives the `t:` reference of a type.
    ///
    /// # Errors
    ///
    /// Returns the [`StoreError`] of an unknown ID or a text above the cap.
    pub fn type_ref(&self, id: TypeId) -> Result<TypeRef, StoreError> {
        self.store.type_ref(id)
    }

    /// Gives the type of a `t:` reference.
    #[must_use]
    pub fn by_ref(&self, reference: &TypeRef) -> Option<TypeId> {
        self.store.by_ref(reference)
    }

    /// Gives the Tier-0 prototype of a linked name. A version suffix after `@` does not count.
    #[must_use]
    pub fn prototype(name: &str) -> Option<&'static Proto> {
        ghidorah_types::proto::builtin().ok()?.get(name)
    }

    /// Gives the store for a change.
    pub(crate) const fn store_mut(&mut self) -> &mut TypeStore {
        &mut self.store
    }
}
