//! The ID newtypes and the one ID parser (design Section 3.5, ADR-0008).
//!
//! Each ID kind has a text prefix, for example `fn:` or `imp:`. [`Id::parse`] reads every kind.
//! The `Display` form of each ID parses back to the same ID, so `parse(display(id)) == id`.
//! The constructors refuse values that have no such text form.
//!
//! | Kind | Type | Text form | Example |
//! |---|---|---|---|
//! | Function | [`FuncId`] | `fn:` and an address | `fn:0x401130` |
//! | Basic block | [`BlockId`] | `bb:` and an address | `bb:0x401145` |
//! | IR op | [`OpId`] | `op:` and an address, `:` and a decimal sequence | `op:0x401a2c:3` |
//! | Import | [`ImportId`] | `imp:<name>`, `imp:<dll>!<name>` or `imp:<dll>!#<ordinal>` | `imp:puts` |
//! | Export | [`ExportId`] | `exp:<name>` or `exp:#<ordinal>` | `exp:main` |
//! | Syscall | [`SyscallId`] | `sys:` and a name or a decimal number | `sys:openat` |
//! | Section | [`SectionId`] | `sec:<index>:<name>` | `sec:14:.text` |
//! | Segment | [`SegmentId`] | `seg:<index>` | `seg:2` |
//! | String | [`StringId`] | `str:` and an address | `str:0x402010` |
//! | Jump table | [`JumpTableId`] | `jt:` and the address of the indirect jump | `jt:0x401200` |
//! | External | [`Address`] in the EXTERNAL space | `ext:` and a hex offset | `ext:0x3` |
//! | File offset | [`FileOffset`] | `file:` and a hex offset | `file:0x1040` |
//! | Symbol | [`SymId`] | `sym:` and the exact symbol name | `sym:puts@GLIBC_2.2.5` |
//! | Variable | [`VarId`] | `var:<entry>/<storage>` | `var:0x401130/stack:-0x14` |
//! | Note | [`NoteId`] | `note:` and a decimal number | `note:7` |
//! | Set | [`SetName`] | `set:` and a name | `set:parsers` |
//! | Type | [`TypeRef`] | `t:<name>` or `t:#<fnv64>` | `t:sockaddr_in` |
//! | Transaction | [`TxId`] | `tx:` and a decimal number | `tx:42` |
//! | Xref | [`RefId`] | `ref:<from>><to>:<kind name>` | `ref:0x401136>0x402010:read` |
//!
//! [`BinaryId`] has no prefix. Its text is 16 hex digits. [`Rev`] is a JSON integer field.

mod composite;
mod names;
mod simple;

use std::fmt;
use std::str::FromStr;

pub use composite::{MAX_REF_KIND, MAX_REG_NAME, RefId, RegVar, Storage, VarId};
pub use names::{
    ExportId, ImportId, MAX_SET_NAME, MAX_SYSCALL_NAME, SectionId, SetName, SymId, SyscallId,
    TypeRef,
};
pub use simple::{
    BinaryId, BlockId, FileOffset, FuncId, JumpTableId, NoteId, OpId, Rev, SegmentId, StringId,
    TxId,
};

use crate::address::Address;
use crate::catalog::ErrorCode;

/// The largest name in an ID, in bytes. It equals the string limit of Section 4.7.
pub const MAX_NAME_LEN: usize = 4096;

/// The largest ID text in bytes. An import ID holds two names.
pub const MAX_ID_TEXT: usize = 2 * MAX_NAME_LEN + 64;

/// The kind of an ID. The order is the prefix order of Section 10.5, rule 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdKind {
    /// `fn:`, a function.
    Func,
    /// `bb:`, a basic block.
    Block,
    /// `op:`, an IR op.
    Op,
    /// `imp:`, an import.
    Import,
    /// `exp:`, an export.
    Export,
    /// `sys:`, a syscall.
    Syscall,
    /// `sec:`, a section.
    Section,
    /// `seg:`, a segment.
    Segment,
    /// `str:`, a string.
    Str,
    /// `jt:`, a jump table.
    JumpTable,
    /// `ext:`, an EXTERNAL address.
    External,
    /// `file:`, a file offset.
    File,
    /// `sym:`, an exact symbol name.
    Sym,
    /// `var:`, a variable.
    Var,
    /// `note:`, a note.
    Note,
    /// `set:`, a named set.
    Set,
    /// `t:`, a type.
    Type,
    /// `tx:`, a transaction.
    Tx,
    /// `ref:`, a cross-reference.
    Ref,
}

impl IdKind {
    /// All kinds in prefix order.
    pub const ALL: [Self; 19] = [
        Self::Func,
        Self::Block,
        Self::Op,
        Self::Import,
        Self::Export,
        Self::Syscall,
        Self::Section,
        Self::Segment,
        Self::Str,
        Self::JumpTable,
        Self::External,
        Self::File,
        Self::Sym,
        Self::Var,
        Self::Note,
        Self::Set,
        Self::Type,
        Self::Tx,
        Self::Ref,
    ];

    /// Gives the text prefix of the kind, for example `fn:`.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Func => "fn:",
            Self::Block => "bb:",
            Self::Op => "op:",
            Self::Import => "imp:",
            Self::Export => "exp:",
            Self::Syscall => "sys:",
            Self::Section => "sec:",
            Self::Segment => "seg:",
            Self::Str => "str:",
            Self::JumpTable => "jt:",
            Self::External => "ext:",
            Self::File => "file:",
            Self::Sym => "sym:",
            Self::Var => "var:",
            Self::Note => "note:",
            Self::Set => "set:",
            Self::Type => "t:",
            Self::Tx => "tx:",
            Self::Ref => "ref:",
        }
    }

    /// Gives the kind whose prefix starts `text`, or `None`.
    ///
    /// No prefix starts another prefix, so at most one kind matches.
    #[must_use]
    pub fn of_text(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| text.starts_with(kind.prefix()))
    }
}

impl fmt::Display for IdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}

/// An error of the ID parser or of an ID constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    /// The text is empty.
    Empty,
    /// The text is longer than [`MAX_ID_TEXT`] bytes.
    TooLong {
        /// The length of the text in bytes.
        len: usize,
    },
    /// The text starts with no registered prefix.
    UnknownPrefix,
    /// The text has the prefix of another kind.
    WrongKind {
        /// The kind that the caller asks for.
        expected: IdKind,
        /// The kind of the text.
        found: IdKind,
    },
    /// One part of the text or of a constructor argument is not valid.
    BadPart {
        /// The kind of the ID, or `None` for a plain address.
        kind: Option<IdKind>,
        /// The name of the part, for example `address` or `ordinal`.
        part: &'static str,
    },
}

impl IdError {
    /// Gives the error code of the error: `INVALID_ARGUMENT`.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::InvalidArgument
    }

    pub(crate) const fn bad(kind: IdKind, part: &'static str) -> Self {
        Self::BadPart {
            kind: Some(kind),
            part,
        }
    }
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("The ID text is empty."),
            Self::TooLong { len } => write!(
                f,
                "The ID text has {len} bytes. The limit is {MAX_ID_TEXT} bytes."
            ),
            Self::UnknownPrefix => f.write_str("The ID text has no registered prefix."),
            Self::WrongKind { expected, found } => write!(
                f,
                "The ID has the prefix {found}. The call needs the prefix {expected}."
            ),
            Self::BadPart {
                kind: Some(kind),
                part,
            } => write!(f, "The {part} part of the {kind} ID is not valid."),
            Self::BadPart { kind: None, part } => write!(f, "The {part} text is not valid."),
        }
    }
}

impl std::error::Error for IdError {}

/// One ID of any kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Id {
    /// A function.
    Func(FuncId),
    /// A basic block.
    Block(BlockId),
    /// An IR op.
    Op(OpId),
    /// An import.
    Import(ImportId),
    /// An export.
    Export(ExportId),
    /// A syscall.
    Syscall(SyscallId),
    /// A section.
    Section(SectionId),
    /// A segment.
    Segment(SegmentId),
    /// A string.
    Str(StringId),
    /// A jump table.
    JumpTable(JumpTableId),
    /// The offset of an EXTERNAL address.
    External(u64),
    /// A file offset.
    File(FileOffset),
    /// An exact symbol name.
    Sym(SymId),
    /// A variable.
    Var(VarId),
    /// A note.
    Note(NoteId),
    /// A named set.
    Set(SetName),
    /// A type.
    Type(TypeRef),
    /// A transaction.
    Tx(TxId),
    /// A cross-reference.
    Ref(RefId),
}

impl Id {
    /// Gives the kind of the ID.
    #[must_use]
    pub const fn kind(&self) -> IdKind {
        match self {
            Self::Func(_) => IdKind::Func,
            Self::Block(_) => IdKind::Block,
            Self::Op(_) => IdKind::Op,
            Self::Import(_) => IdKind::Import,
            Self::Export(_) => IdKind::Export,
            Self::Syscall(_) => IdKind::Syscall,
            Self::Section(_) => IdKind::Section,
            Self::Segment(_) => IdKind::Segment,
            Self::Str(_) => IdKind::Str,
            Self::JumpTable(_) => IdKind::JumpTable,
            Self::External(_) => IdKind::External,
            Self::File(_) => IdKind::File,
            Self::Sym(_) => IdKind::Sym,
            Self::Var(_) => IdKind::Var,
            Self::Note(_) => IdKind::Note,
            Self::Set(_) => IdKind::Set,
            Self::Type(_) => IdKind::Type,
            Self::Tx(_) => IdKind::Tx,
            Self::Ref(_) => IdKind::Ref,
        }
    }

    /// Parses the text form of any ID kind.
    ///
    /// The text must start with a registered prefix. The rest must be an exact form of that kind.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::Empty`], [`IdError::TooLong`], [`IdError::UnknownPrefix`] or
    /// [`IdError::BadPart`].
    pub fn parse(text: &str) -> Result<Self, IdError> {
        if text.is_empty() {
            return Err(IdError::Empty);
        }
        if text.len() > MAX_ID_TEXT {
            return Err(IdError::TooLong { len: text.len() });
        }
        let kind = IdKind::of_text(text).ok_or(IdError::UnknownPrefix)?;
        let body = text
            .strip_prefix(kind.prefix())
            .ok_or(IdError::UnknownPrefix)?;
        Self::parse_body(kind, body)
    }

    /// Parses the text after the prefix of `kind`.
    fn parse_body(kind: IdKind, body: &str) -> Result<Self, IdError> {
        let address = || Address::parse(body).map_err(|_| IdError::bad(kind, "address"));
        let hex = |part| crate::hex::parse_u64(body).ok_or_else(|| IdError::bad(kind, part));
        let number = |part| parse_dec(body).ok_or_else(|| IdError::bad(kind, part));
        Ok(match kind {
            IdKind::Func => Self::Func(FuncId(address()?)),
            IdKind::Block => Self::Block(BlockId(address()?)),
            IdKind::Op => Self::Op(OpId::parse_body(body)?),
            IdKind::Import => Self::Import(ImportId::parse_body(body)?),
            IdKind::Export => Self::Export(ExportId::parse_body(body)?),
            IdKind::Syscall => Self::Syscall(SyscallId::parse_body(body)?),
            IdKind::Section => Self::Section(SectionId::parse_body(body)?),
            IdKind::Segment => Self::Segment(SegmentId(
                parse_dec_as(body).ok_or_else(|| IdError::bad(kind, "index"))?,
            )),
            IdKind::Str => Self::Str(StringId(address()?)),
            IdKind::JumpTable => Self::JumpTable(JumpTableId(address()?)),
            IdKind::External => Self::External(hex("offset")?),
            IdKind::File => Self::File(FileOffset(hex("offset")?)),
            IdKind::Sym => Self::Sym(SymId::new(body)?),
            IdKind::Var => Self::Var(VarId::parse_body(body)?),
            IdKind::Note => Self::Note(NoteId(number("number")?)),
            IdKind::Set => Self::Set(SetName::new(body)?),
            IdKind::Type => Self::Type(TypeRef::parse_body(body)?),
            IdKind::Tx => Self::Tx(TxId(number("number")?)),
            IdKind::Ref => Self::Ref(RefId::parse_body(body)?),
        })
    }

    /// Gives the address of an ID that names one address: `fn:`, `bb:`, `str:`, `jt:` and `ext:`.
    #[must_use]
    pub const fn address(&self) -> Option<Address> {
        match self {
            Self::Func(FuncId(a))
            | Self::Block(BlockId(a))
            | Self::Str(StringId(a))
            | Self::JumpTable(JumpTableId(a)) => Some(*a),
            Self::External(off) => Some(Address::external(*off)),
            _ => None,
        }
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Func(v) => v.fmt(f),
            Self::Block(v) => v.fmt(f),
            Self::Op(v) => v.fmt(f),
            Self::Import(v) => v.fmt(f),
            Self::Export(v) => v.fmt(f),
            Self::Syscall(v) => v.fmt(f),
            Self::Section(v) => v.fmt(f),
            Self::Segment(v) => v.fmt(f),
            Self::Str(v) => v.fmt(f),
            Self::JumpTable(v) => v.fmt(f),
            Self::External(off) => Address::external(*off).fmt(f),
            Self::File(v) => v.fmt(f),
            Self::Sym(v) => v.fmt(f),
            Self::Var(v) => v.fmt(f),
            Self::Note(v) => v.fmt(f),
            Self::Set(v) => v.fmt(f),
            Self::Type(v) => v.fmt(f),
            Self::Tx(v) => v.fmt(f),
            Self::Ref(v) => v.fmt(f),
        }
    }
}

/// Parses decimal digits into a `u64`. Empty text and an overflow give `None`.
pub(crate) fn parse_dec(text: &str) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    text.bytes().try_fold(0u64, |acc, b| {
        let d = b.is_ascii_digit().then(|| u64::from(b - b'0'))?;
        acc.checked_mul(10)?.checked_add(d)
    })
}

/// Parses decimal digits into a narrower integer type. A value out of range gives `None`.
pub(crate) fn parse_dec_as<T: TryFrom<u64>>(text: &str) -> Option<T> {
    T::try_from(parse_dec(text)?).ok()
}

/// Tells if `text` holds only ASCII digits. Empty text gives `true`.
pub(crate) fn all_digits(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_digit())
}

impl FromStr for Id {
    type Err = IdError;

    fn from_str(text: &str) -> Result<Self, IdError> {
        Self::parse(text)
    }
}

/// Implements `FromStr` for one ID newtype through [`Id::parse`].
macro_rules! from_str_via_id {
    ($ty:ident, $variant:ident) => {
        impl ::std::str::FromStr for $ty {
            type Err = $crate::id::IdError;

            fn from_str(text: &str) -> Result<Self, $crate::id::IdError> {
                match $crate::id::Id::parse(text)? {
                    $crate::id::Id::$variant(v) => Ok(v),
                    other => Err($crate::id::IdError::WrongKind {
                        expected: $crate::id::IdKind::$variant,
                        found: other.kind(),
                    }),
                }
            }
        }
    };
}

pub(crate) use from_str_via_id;
