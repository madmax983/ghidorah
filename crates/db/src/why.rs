//! Why-records (design Section 3.4, ADR-0023).
//!
//! Every ANALYSIS fact has a [`Why`]: a rule code and the keys of its premises. The premise
//! graph has no cycle (Section 3.11, invariant 6). The store keeps no creation order, so a
//! change of one record changes no other record (ADR-0031).
//!
//! The analysis crate owns the closed rule catalog and its doc lines. This module keeps the
//! code text: `R_` and upper case letters, digits and `_`, for example `R_FDE_START`.

#[cfg(test)]
mod tests;

mod rows;
mod store;

pub use rows::WhyRows;
pub use store::WhyStore;

use std::fmt;
use std::sync::Arc;

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
///
/// A clone shares the text. Many records of one rule hold one copy of its code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleCode(Arc<str>);

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
        Ok(Self(Arc::from(text)))
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
