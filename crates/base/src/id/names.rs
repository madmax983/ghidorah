//! IDs that hold a name: symbols, imports, exports, syscalls, sections, sets and types.
//!
//! Each type keeps its fields private. The constructors refuse a name that has no
//! text form that parses back to the same ID.

use std::fmt;

use super::{IdError, IdKind, MAX_NAME_LEN, all_digits, from_str_via_id, parse_dec};
use crate::hex;

/// The largest syscall name in bytes.
pub const MAX_SYSCALL_NAME: usize = 64;

/// The largest set name in bytes.
pub const MAX_SET_NAME: usize = 64;

/// An exact symbol name. Text: `sym:` and the name, for example `sym:puts@GLIBC_2.2.5`.
///
/// The name is not empty and has at most [`MAX_NAME_LEN`] bytes. It can hold any character.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymId(String);

impl SymId {
    /// Makes the ID of the symbol `name`.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] for an empty name or a name above [`MAX_NAME_LEN`] bytes.
    pub fn new(name: &str) -> Result<Self, IdError> {
        if name_fits(name) {
            Ok(Self(name.to_string()))
        } else {
            Err(IdError::bad(IdKind::Sym, "name"))
        }
    }

    /// Gives the symbol name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SymId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sym:{}", self.0)
    }
}

/// The three forms of an import.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ImportRepr {
    Elf(String),
    Named { dll: String, name: String },
    Ordinal { dll: String, ordinal: u16 },
}

/// An import.
///
/// - ELF: `imp:<name>`. ELF does not bind a library. A name with a `!` writes `imp:!<name>`.
/// - PE by name: `imp:<dll>!<name>`. The DLL name is ASCII lower case.
/// - PE by ordinal: `imp:<dll>!#<ordinal>`.
///
/// The parser splits at the first `!`. Text before the first `!` is the DLL name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImportId(ImportRepr);

impl ImportId {
    /// Makes an ELF import.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] for an empty name or a name above [`MAX_NAME_LEN`] bytes.
    pub fn elf(name: &str) -> Result<Self, IdError> {
        if !name_fits(name) {
            return Err(IdError::bad(IdKind::Import, "name"));
        }
        Ok(Self(ImportRepr::Elf(name.to_string())))
    }

    /// Makes a PE import by name. The DLL name changes to ASCII lower case.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] for an empty DLL name, a DLL name with `!` or an empty name.
    /// A name of the form `#<digits>` and a part above [`MAX_NAME_LEN`] bytes give it too.
    pub fn pe_by_name(dll: &str, name: &str) -> Result<Self, IdError> {
        let dll = dll_name(dll)?;
        if !name_fits(name) || is_ordinal_form(name) {
            return Err(IdError::bad(IdKind::Import, "name"));
        }
        Ok(Self(ImportRepr::Named {
            dll,
            name: name.to_string(),
        }))
    }

    /// Makes a PE import by ordinal. The DLL name changes to ASCII lower case.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] for an empty DLL name, a DLL name with `!` or a DLL name
    /// above [`MAX_NAME_LEN`] bytes.
    pub fn pe_by_ordinal(dll: &str, ordinal: u16) -> Result<Self, IdError> {
        Ok(Self(ImportRepr::Ordinal {
            dll: dll_name(dll)?,
            ordinal,
        }))
    }

    /// Gives the DLL name of a PE import, in lower case.
    #[must_use]
    pub fn lib(&self) -> Option<&str> {
        match &self.0 {
            ImportRepr::Elf(_) => None,
            ImportRepr::Named { dll, .. } | ImportRepr::Ordinal { dll, .. } => Some(dll),
        }
    }

    /// Gives the import name, or `None` for an import by ordinal.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match &self.0 {
            ImportRepr::Elf(name) | ImportRepr::Named { name, .. } => Some(name),
            ImportRepr::Ordinal { .. } => None,
        }
    }

    /// Gives the ordinal of an import by ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> Option<u16> {
        match self.0 {
            ImportRepr::Ordinal { ordinal, .. } => Some(ordinal),
            ImportRepr::Elf(_) | ImportRepr::Named { .. } => None,
        }
    }

    pub(crate) fn parse_body(body: &str) -> Result<Self, IdError> {
        match body.split_once('!') {
            None => Self::elf(body),
            Some(("", name)) => Self::elf(name),
            Some((dll, item)) => match item.strip_prefix('#') {
                Some(digits) if all_digits(digits) => {
                    let ordinal = parse_dec(digits)
                        .and_then(|n| u16::try_from(n).ok())
                        .ok_or(IdError::bad(IdKind::Import, "ordinal"))?;
                    Self::pe_by_ordinal(dll, ordinal)
                }
                _ => Self::pe_by_name(dll, item),
            },
        }
    }
}

impl fmt::Display for ImportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ImportRepr::Elf(name) if name.contains('!') => write!(f, "imp:!{name}"),
            ImportRepr::Elf(name) => write!(f, "imp:{name}"),
            ImportRepr::Named { dll, name } => write!(f, "imp:{dll}!{name}"),
            ImportRepr::Ordinal { dll, ordinal } => write!(f, "imp:{dll}!#{ordinal}"),
        }
    }
}

/// The item of an export: a name or an ordinal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ExportItem {
    Name(String),
    Ordinal(u32),
}

/// An export. Text: `exp:<name>`, or `exp:#<ordinal>` for a PE export without a name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExportId(ExportItem);

impl ExportId {
    /// Makes an export by name.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] for an empty name, a name of the form `#<digits>` or a name
    /// above [`MAX_NAME_LEN`] bytes.
    pub fn by_name(name: &str) -> Result<Self, IdError> {
        if !name_fits(name) || is_ordinal_form(name) {
            return Err(IdError::bad(IdKind::Export, "name"));
        }
        Ok(Self(ExportItem::Name(name.to_string())))
    }

    /// Makes an export without a name, by its ordinal.
    #[must_use]
    pub const fn by_ordinal(ordinal: u32) -> Self {
        Self(ExportItem::Ordinal(ordinal))
    }

    /// Gives the export name, or `None` for an export by ordinal.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match &self.0 {
            ExportItem::Name(name) => Some(name),
            ExportItem::Ordinal(_) => None,
        }
    }

    /// Gives the ordinal of an export by ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> Option<u32> {
        match self.0 {
            ExportItem::Ordinal(ordinal) => Some(ordinal),
            ExportItem::Name(_) => None,
        }
    }

    pub(crate) fn parse_body(body: &str) -> Result<Self, IdError> {
        match body.strip_prefix('#') {
            Some(digits) if all_digits(digits) => parse_dec(digits)
                .and_then(|n| u32::try_from(n).ok())
                .map(Self::by_ordinal)
                .ok_or(IdError::bad(IdKind::Export, "ordinal")),
            _ => Self::by_name(body),
        }
    }
}

impl fmt::Display for ExportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ExportItem::Name(name) => write!(f, "exp:{name}"),
            ExportItem::Ordinal(n) => write!(f, "exp:#{n}"),
        }
    }
}

/// The value of a syscall ID: a name or a number.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SyscallItem {
    Number(u16),
    Name(String),
}

/// A syscall. Text: `sys:` and a name (`sys:openat`) or a decimal number (`sys:257`).
///
/// A name matches `[a-z_][a-z0-9_]*` with at most [`MAX_SYSCALL_NAME`] bytes.
/// The syscall table of `ghidorah-types` maps names to numbers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyscallId(SyscallItem);

impl SyscallId {
    /// Makes the ID of a syscall number.
    #[must_use]
    pub const fn by_number(number: u16) -> Self {
        Self(SyscallItem::Number(number))
    }

    /// Makes the ID of a syscall name.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] when the name does not match the syscall name grammar.
    pub fn by_name(name: &str) -> Result<Self, IdError> {
        let lower = |b: u8| b.is_ascii_lowercase() || b == b'_';
        let first_ok = name.bytes().next().is_some_and(lower);
        let rest_ok = name.bytes().all(|b| lower(b) || b.is_ascii_digit());
        if first_ok && rest_ok && name.len() <= MAX_SYSCALL_NAME {
            Ok(Self(SyscallItem::Name(name.to_string())))
        } else {
            Err(IdError::bad(IdKind::Syscall, "name"))
        }
    }

    /// Gives the syscall name, or `None` for a number.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match &self.0 {
            SyscallItem::Name(name) => Some(name),
            SyscallItem::Number(_) => None,
        }
    }

    /// Gives the syscall number, or `None` for a name.
    #[must_use]
    pub const fn number(&self) -> Option<u16> {
        match self.0 {
            SyscallItem::Number(number) => Some(number),
            SyscallItem::Name(_) => None,
        }
    }

    pub(crate) fn parse_body(body: &str) -> Result<Self, IdError> {
        if !body.is_empty() && all_digits(body) {
            parse_dec(body)
                .and_then(|n| u16::try_from(n).ok())
                .map(Self::by_number)
                .ok_or(IdError::bad(IdKind::Syscall, "number"))
        } else {
            Self::by_name(body)
        }
    }
}

impl fmt::Display for SyscallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            SyscallItem::Number(n) => write!(f, "sys:{n}"),
            SyscallItem::Name(name) => write!(f, "sys:{name}"),
        }
    }
}

/// A section: its index and its name. Text: `sec:<index>:<name>`, for example `sec:14:.text`.
///
/// The name can be empty and can hold any character, `:` included.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionId {
    index: u16,
    name: String,
}

impl SectionId {
    /// Makes the ID of the section at `index` with `name`.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] for a name above [`MAX_NAME_LEN`] bytes.
    pub fn new(index: u16, name: &str) -> Result<Self, IdError> {
        if name.len() > MAX_NAME_LEN {
            return Err(IdError::bad(IdKind::Section, "name"));
        }
        Ok(Self {
            index,
            name: name.to_string(),
        })
    }

    /// Gives the section index.
    #[must_use]
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Gives the section name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn parse_body(body: &str) -> Result<Self, IdError> {
        let (index, name) = body
            .split_once(':')
            .ok_or(IdError::bad(IdKind::Section, "name"))?;
        let index = parse_dec(index)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(IdError::bad(IdKind::Section, "index"))?;
        Self::new(index, name)
    }
}

impl fmt::Display for SectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sec:{}:{}", self.index, self.name)
    }
}

/// The name of a named set. Text: `set:parsers`.
///
/// A name matches `[A-Za-z0-9_.-]+` with at most [`MAX_SET_NAME`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SetName(String);

impl SetName {
    /// Makes a set name.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] when the name does not match the set name grammar.
    pub fn new(name: &str) -> Result<Self, IdError> {
        let ok_byte = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-');
        if !name.is_empty() && name.len() <= MAX_SET_NAME && name.bytes().all(ok_byte) {
            Ok(Self(name.to_string()))
        } else {
            Err(IdError::bad(IdKind::Set, "name"))
        }
    }

    /// Gives the set name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "set:{}", self.0)
    }
}

/// The value of a type ID: a name or the FNV-1a hash of the canonical C text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum TypeItem {
    Named(String),
    Anon(u64),
}

/// A type outside one program. Text: `t:<name>` for a named type, `t:#<fnv64>` for others.
///
/// The hash form writes 16 lower case hex digits. A name is not empty, does not start
/// with `#` and has at most [`MAX_NAME_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeRef(TypeItem);

impl TypeRef {
    /// Makes the ID of a named type.
    ///
    /// # Errors
    ///
    /// Returns [`IdError::BadPart`] for an empty name, a name that starts with `#` or a name
    /// above [`MAX_NAME_LEN`] bytes.
    pub fn named(name: &str) -> Result<Self, IdError> {
        if name_fits(name) && !name.starts_with('#') {
            Ok(Self(TypeItem::Named(name.to_string())))
        } else {
            Err(IdError::bad(IdKind::Type, "name"))
        }
    }

    /// Makes the ID of a type without a name, from the hash of its canonical C text.
    #[must_use]
    pub const fn anon(hash: u64) -> Self {
        Self(TypeItem::Anon(hash))
    }

    /// Gives the type name, or `None` for a type without a name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match &self.0 {
            TypeItem::Named(name) => Some(name),
            TypeItem::Anon(_) => None,
        }
    }

    /// Gives the hash of a type without a name.
    #[must_use]
    pub const fn hash(&self) -> Option<u64> {
        match self.0 {
            TypeItem::Anon(hash) => Some(hash),
            TypeItem::Named(_) => None,
        }
    }

    pub(crate) fn parse_body(body: &str) -> Result<Self, IdError> {
        match body.strip_prefix('#') {
            Some(digits) => hex::parse_digits(digits)
                .map(Self::anon)
                .ok_or(IdError::bad(IdKind::Type, "hash")),
            None => Self::named(body),
        }
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            TypeItem::Named(name) => write!(f, "t:{name}"),
            TypeItem::Anon(hash) => write!(f, "t:#{hash:016x}"),
        }
    }
}

/// Tells if a name fits in an ID: not empty and at most [`MAX_NAME_LEN`] bytes.
pub(crate) const fn name_fits(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME_LEN
}

/// Tells if a name looks like an ordinal: `#` and digits only, `#` alone included.
fn is_ordinal_form(name: &str) -> bool {
    name.strip_prefix('#').is_some_and(all_digits)
}

/// Checks a DLL name and gives it in ASCII lower case.
fn dll_name(dll: &str) -> Result<String, IdError> {
    if name_fits(dll) && !dll.contains('!') {
        Ok(dll.to_ascii_lowercase())
    } else {
        Err(IdError::bad(IdKind::Import, "dll"))
    }
}

from_str_via_id!(SymId, Sym);
from_str_via_id!(ImportId, Import);
from_str_via_id!(ExportId, Export);
from_str_via_id!(SyscallId, Syscall);
from_str_via_id!(SectionId, Section);
from_str_via_id!(SetName, Set);
from_str_via_id!(TypeRef, Type);
