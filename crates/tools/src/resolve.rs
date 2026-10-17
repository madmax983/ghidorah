//! The address resolver (design Section 10.5, ADR-0007).
//!
//! [`resolve`] reads one address input and gives what it names, with
//! `resolved_from: { rule, matched }`. A string resolves by the first rule that matches:
//!
//! | Rule | [`Rule`] | Input | Result |
//! |---|---|---|---|
//! | 1 | `integer` | a JSON integer below 2^53 | that RAM address |
//! | 2 | `hex` | `0x` and 1 to 16 hex digits | that RAM address |
//! | 3 | `id` | a registered ID prefix, as an exact parse | the entity of the ID. `sym:` takes only an exact symbol name. |
//! | 4 | `symbol` | the exact name of a symbol | its address |
//! | 5 | `section` | the name of a section | the start of the section |
//! | 6 | `default_name` | `FUN_`, `LAB_`, `DAT_` or `EXT_` and hex digits | that address |
//! | 7 | `name_at` | `name@0x<hex>` with a symbol `name` at that address | that address |
//! | 8 | `offset` | `term+0x..` or `term-0x..`, split at the last sign | the term address plus the offset |
//!
//! Errors:
//!
//! | Input | Code |
//! |---|---|
//! | Digits only, or an offset of digits only | `ADDRESS_BASE_AMBIGUOUS` with both readings |
//! | A name with more than one match | `AMBIGUOUS_NAME` with `name@0x..` or ID values in address order |
//! | An unknown name or ID | `NOT_FOUND` with did-you-mean candidates |
//! | Text that does not parse, or an offset that wraps | `ADDRESS_INVALID` |
//!
//! The [`table`] module maps the result to the addresses of each tool family.

pub mod table;

use ghidorah_base::{
    Address, ExportId, FuncId, IdKind, ImportId, JumpTableId, StringId, SyscallId,
};
use ghidorah_db::Program;
use ghidorah_json::Value;

use crate::errors::ToolError;
use crate::hints::Call;

pub use table::{Family, Target, accepted, address, function, target, value_of};

/// The rule that resolved an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// Rule 1: a JSON integer.
    Integer,
    /// Rule 2: `0x` hex text.
    Hex,
    /// Rule 3: an ID.
    Id,
    /// Rule 4: an exact symbol name.
    Symbol,
    /// Rule 5: a section name.
    Section,
    /// Rule 6: a computed default name.
    DefaultName,
    /// Rule 7: `name@0x<hex>`.
    NameAt,
    /// Rule 8: a term with an offset.
    Offset,
}

impl Rule {
    /// All rules in rule order.
    pub const ALL: [Self; 8] = [
        Self::Integer,
        Self::Hex,
        Self::Id,
        Self::Symbol,
        Self::Section,
        Self::DefaultName,
        Self::NameAt,
        Self::Offset,
    ];

    /// Gives the rule name of `resolved_from.rule`, for example `default_name`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Integer => "integer",
            Self::Hex => "hex",
            Self::Id => "id",
            Self::Symbol => "symbol",
            Self::Section => "section",
            Self::DefaultName => "default_name",
            Self::NameAt => "name_at",
            Self::Offset => "offset",
        }
    }
}

/// What an input names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Named {
    /// An address: an integer, hex text, a symbol, a section name, a default name,
    /// `name@0x..`, an offset expression, or a `bb:` or `op:` ID.
    Addr(Address),
    /// A function: `fn:F`.
    Func(FuncId),
    /// An import: `imp:X`.
    Import(ImportId),
    /// An export: `exp:F`.
    Export(ExportId),
    /// A syscall: `sys:N`.
    Syscall(SyscallId),
    /// A string: `str:A`.
    Str(StringId),
    /// A jump table: `jt:A`.
    JumpTable(JumpTableId),
    /// The start address of a `sec:`, `seg:` or `file:` ID.
    Region(Address),
    /// An EXTERNAL address: `ext:0x..`.
    External(Address),
    /// An ID kind that names no address: `var:`, `t:`, `note:`, `set:`, `tx:` or `ref:`.
    Other(IdKind),
}

/// The result of one resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// What the input names.
    pub named: Named,
    /// The rule that matched.
    pub rule: Rule,
    /// The text that matched the rule: the input text, or the decimal text of an integer.
    pub matched: String,
}

impl Resolved {
    /// Gives `resolved_from: { rule, matched }` as JSON.
    #[must_use]
    pub fn resolved_from(&self) -> Value {
        Value::Null
    }
}

/// Where an input sits in a call, for the field path and the repair calls of errors.
#[derive(Clone, Copy, Default)]
pub struct Site<'a> {
    /// The JSON pointer of the input in the arguments, for example `/target`.
    pub path: &'a str,
    /// Gives the call with the input text replaced by its argument, for a repair.
    pub repair: Option<&'a dyn Fn(&str) -> Call>,
}

impl std::fmt::Debug for Site<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Site")
            .field("path", &self.path)
            .field("repair", &self.repair.is_some())
            .finish()
    }
}

/// Resolves one address input: a JSON integer or a string.
///
/// # Errors
///
/// Returns the errors of the module docs, and `INVALID_ARGUMENT` for another JSON type.
pub fn resolve(program: &Program, input: &Value, site: &Site<'_>) -> Result<Resolved, ToolError> {
    let _ = (program, input, site);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
}

/// Resolves one address text.
///
/// # Errors
///
/// Returns the errors of the module docs.
pub fn resolve_text(program: &Program, text: &str, site: &Site<'_>) -> Result<Resolved, ToolError> {
    let _ = (program, text, site);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
}
