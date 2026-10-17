//! IDs with more than one part: variables and cross-references.

use std::fmt;

use super::{FuncId, IdError, IdKind, from_str_via_id};
use crate::address::Address;

/// The largest register name in bytes.
pub const MAX_REG_NAME: usize = 16;

/// The largest xref kind name in bytes.
pub const MAX_REF_KIND: usize = 32;

/// The storage of a variable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Storage {
    /// The parameter with this 0-based index. Text: `param:<n>`.
    Param(u16),
    /// A stack slot at this signed offset from the frame base. Text: `stack:-0x14`.
    Stack(i64),
    /// A register value. Text: `reg:<name>@<def addr>`, for example `reg:rax@0x401136`.
    Reg(RegVar),
    /// The return value. Text: `ret`.
    Ret,
}

/// A register variable: a register name and the RAM address of its definition.
///
/// A name matches `[a-z][a-z0-9]*` with at most [`MAX_REG_NAME`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegVar {
    name: String,
    def: u64,
}

impl RegVar {
    /// Makes a register variable.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] when the name does not match the register name grammar.
    pub fn new(name: &str, def: u64) -> Result<Self, IdError> {
        let _ = (name, def);
        Err(IdError::bad(IdKind::Var, "register"))
    }

    /// Gives the register name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gives the RAM address of the definition.
    #[must_use]
    pub const fn def(&self) -> u64 {
        self.def
    }
}

/// A variable: the entry of its function and its storage. Text: `var:<entry>/<storage>`.
///
/// Example: `var:0x401130/stack:-0x14`. A rename never changes a variable ID.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VarId {
    /// The function of the variable.
    pub func: FuncId,
    /// The storage of the variable.
    pub storage: Storage,
}

impl VarId {
    pub(crate) fn parse_body(body: &str) -> Result<Self, IdError> {
        let _ = body;
        Err(IdError::bad(IdKind::Var, "entry"))
    }
}

impl fmt::Display for Storage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        f.write_str("")
    }
}

impl fmt::Display for VarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        f.write_str("")
    }
}

/// A cross-reference: its source, its target and its kind name.
///
/// Text: `ref:<from>><to>:<kind name>`, for example `ref:0x401136>0x402010:read`.
/// A kind name matches `[a-z][a-z0-9_]*` with at most [`MAX_REF_KIND`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefId {
    from: Address,
    to: Address,
    kind: String,
}

impl RefId {
    /// Makes the ID of a reference.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] when the kind name does not match the kind name grammar.
    pub fn new(from: Address, to: Address, kind: &str) -> Result<Self, IdError> {
        let _ = (from, to, kind);
        Err(IdError::bad(IdKind::Ref, "kind"))
    }

    /// Gives the source address.
    #[must_use]
    pub const fn from(&self) -> Address {
        self.from
    }

    /// Gives the target address.
    #[must_use]
    pub const fn to(&self) -> Address {
        self.to
    }

    /// Gives the kind name, for example `read` or `call`.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub(crate) fn parse_body(body: &str) -> Result<Self, IdError> {
        let _ = body;
        Err(IdError::bad(IdKind::Ref, "from"))
    }
}

impl fmt::Display for RefId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        f.write_str("")
    }
}

from_str_via_id!(VarId, Var);
from_str_via_id!(RefId, Ref);
