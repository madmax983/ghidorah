//! IDs with more than one part: variables and cross-references.

use std::fmt;

use super::{FuncId, IdError, IdKind, from_str_via_id, parse_dec_as};
use crate::address::Address;
use crate::hex;

/// The largest register name in bytes.
pub const MAX_REG_NAME: usize = 16;

/// The longest kind name of an xref, in bytes.
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
        let first_ok = name.bytes().next().is_some_and(|b| b.is_ascii_lowercase());
        let rest_ok = name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        if first_ok && rest_ok && name.len() <= MAX_REG_NAME {
            Ok(Self {
                name: name.to_string(),
                def,
            })
        } else {
            Err(IdError::bad(IdKind::Var, "register"))
        }
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

impl Storage {
    /// Parses the storage part of a variable ID.
    fn parse(text: &str) -> Result<Self, IdError> {
        let bad = |part| IdError::bad(IdKind::Var, part);
        if text == "ret" {
            return Ok(Self::Ret);
        }
        if let Some(n) = text.strip_prefix("param:") {
            return parse_dec_as::<u16>(n)
                .map(Self::Param)
                .ok_or_else(|| bad("param"));
        }
        if let Some(offset) = text.strip_prefix("stack:") {
            let value = match offset.strip_prefix('-') {
                Some(magnitude) => {
                    hex::parse_u64(magnitude).and_then(|m| 0i64.checked_sub_unsigned(m))
                }
                None => hex::parse_u64(offset).and_then(|v| i64::try_from(v).ok()),
            };
            return value.map(Self::Stack).ok_or_else(|| bad("stack"));
        }
        if let Some(reg) = text.strip_prefix("reg:") {
            let (name, def) = reg.rsplit_once('@').ok_or_else(|| bad("register"))?;
            let def = hex::parse_u64(def).ok_or_else(|| bad("register"))?;
            return RegVar::new(name, def).map(Self::Reg);
        }
        Err(bad("storage"))
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
        let (entry, storage) = body
            .split_once('/')
            .ok_or(IdError::bad(IdKind::Var, "storage"))?;
        let entry = Address::parse(entry).map_err(|_| IdError::bad(IdKind::Var, "entry"))?;
        Ok(Self {
            func: FuncId(entry),
            storage: Storage::parse(storage)?,
        })
    }
}

impl fmt::Display for Storage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Param(n) => write!(f, "param:{n}"),
            Self::Stack(v) if *v < 0 => write!(f, "stack:-{:#x}", v.unsigned_abs()),
            Self::Stack(v) => write!(f, "stack:{v:#x}"),
            Self::Reg(reg) => write!(f, "reg:{}@{:#x}", reg.name, reg.def),
            Self::Ret => f.write_str("ret"),
        }
    }
}

impl fmt::Display for VarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "var:{}/{}", self.func.0, self.storage)
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
        let first_ok = kind.bytes().next().is_some_and(|b| b.is_ascii_lowercase());
        let rest_ok = kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if first_ok && rest_ok && kind.len() <= MAX_REF_KIND {
            Ok(Self {
                from,
                to,
                kind: kind.to_string(),
            })
        } else {
            Err(IdError::bad(IdKind::Ref, "kind"))
        }
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
        let bad = |part| IdError::bad(IdKind::Ref, part);
        let (from, rest) = body.split_once('>').ok_or_else(|| bad("to"))?;
        let (to, kind) = rest.rsplit_once(':').ok_or_else(|| bad("kind"))?;
        let from = Address::parse(from).map_err(|_| bad("from"))?;
        let to = Address::parse(to).map_err(|_| bad("to"))?;
        Self::new(from, to, kind)
    }
}

impl fmt::Display for RefId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ref:{}>{}:{}", self.from, self.to, self.kind)
    }
}

from_str_via_id!(VarId, Var);
from_str_via_id!(RefId, Ref);
