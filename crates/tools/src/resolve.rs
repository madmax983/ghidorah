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
//! The [`table`] module maps the result to the addresses of each tool family. An `imp:` ID
//! stands for the PLT stub of an ELF import or the IAT thunk of a PE import. Else it stands
//! for the import slot ([`import_entry`]).

mod errors;
pub(crate) use errors::hex_repair;
mod rules;
pub mod table;

use ghidorah_base::{
    Address, ExportId, FuncId, IdKind, ImportId, JumpTableId, StringId, SyscallId, addr_expr,
};
use ghidorah_db::{ImportRow, Program};
use ghidorah_json::Value;

use crate::errors::ToolError;
use crate::hints::Call;

pub use table::{Family, Target, accepted, address, function, target, value_of};

/// Gives the entry of the stub or thunk of an import. A PLT stub of the loader comes first.
/// Else the entry is the function with the `thunk` flag that jumps through the import slot.
#[must_use]
pub fn import_entry(program: &Program, row: &ImportRow) -> Option<Address> {
    if row.stub.is_some() {
        return row.stub;
    }
    program
        .refs_to(row.ext)
        .iter()
        .map(|r| r.value.key.from)
        .filter(|from| {
            program
                .func(FuncId(*from))
                .is_some_and(|f| f.func.flags.thunk)
        })
        .min()
}

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
        Value::object([
            ("rule", Value::from(self.rule.name())),
            ("matched", Value::from(self.matched.as_str())),
        ])
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
    match input {
        Value::Number(n) => {
            let value = if n.is_integer() { n.as_u64() } else { None };
            match value.map(addr_expr::from_integer) {
                Some(Ok(_)) => Ok(Resolved {
                    named: Named::Addr(Address::ram(value.unwrap_or_default())),
                    rule: Rule::Integer,
                    matched: n.as_str().to_owned(),
                }),
                Some(Err(e)) => Err(errors::address_invalid(site, e.repair_text())),
                None => Err(errors::address_invalid(site, None)),
            }
        }
        Value::String(text) => resolve_text(program, text, site),
        _ => Err(errors::invalid(
            "an address: a 0x hex string, a name, an ID or an integer below 2^53",
            site,
        )),
    }
}

/// Resolves one address text.
///
/// # Errors
///
/// Returns the errors of the module docs.
pub fn resolve_text(program: &Program, text: &str, site: &Site<'_>) -> Result<Resolved, ToolError> {
    let expr =
        addr_expr::parse(text).map_err(|e| errors::address_invalid(site, e.repair_text()))?;
    let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
    rules::expr(program, &expr, trimmed, site)
}
