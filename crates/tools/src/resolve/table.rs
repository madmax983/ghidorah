//! The target table (design Section 10.5): what each input kind means to each tool family.
//!
//! | Input kind | [`Family::Address`] | [`Family::Function`] | [`Family::XrefTo`] | [`Family::XrefFrom`] |
//! |---|---|---|---|---|
//! | address, name, `bb:`, `op:` | that address | the owner function, else `NOT_IN_FUNCTION` | refs to the address | refs from the one instruction |
//! | `fn:F`, `exp:F` | the entry of F | F | refs to the entry | refs from the body of F |
//! | `imp:X` | the stub or IAT thunk, else the slot, else the EXTERNAL address | the stub or thunk function, else invalid | the sites of the import | invalid |
//! | `sys:N` | invalid | invalid | the syscall sites | invalid |
//! | `str:A` | A | invalid | refs to A | invalid |
//! | `jt:A` | A | the owner function | refs to A | the case edges of A |
//! | `sec:`, `seg:`, `file:` | the start address | invalid | invalid | invalid |
//! | `ext:0x..` | that EXTERNAL address | invalid | refs to it | invalid |
//! | `var:`, `t:`, `note:`, `set:`, `tx:`, `ref:` | invalid | invalid | invalid | invalid |
//!
//! "Invalid" gives `INVALID_ARGUMENT` with `details.accepted`. The address family needs a
//! mapped RAM address or an EXTERNAL address: else `ADDRESS_UNMAPPED` with the nearest mapped
//! addresses.

use ghidorah_base::{Address, FuncId, ImportId, JumpTableId, SyscallId};
use ghidorah_db::{ImportRow, Program};
use ghidorah_json::Value;

use super::{Named, Resolved, Site, errors};
use crate::errors::ToolError;

/// A tool family of the target table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// `mem_read`, `addr_info`, `comment_set` and every `at` argument.
    Address,
    /// `func_get`, `func_edit target` and the `fn` arguments of relations.
    Function,
    /// `xref_list` with direction `to`.
    XrefTo,
    /// `xref_list` with direction `from`.
    XrefFrom,
}

/// What a tool of one family acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// One address.
    Addr(Address),
    /// One function.
    Func(FuncId),
    /// The references to one address.
    RefsTo(Address),
    /// The call, jump and data sites of an import: stub, slot and direct sites.
    ImportSites(ImportId),
    /// The syscall sites with one number.
    SyscallSites(SyscallId),
    /// The references from one instruction.
    RefsFromInsn(Address),
    /// The references whose source is in the body of a function.
    RefsFromBody(FuncId),
    /// The case edges of a jump table.
    CaseEdges(JumpTableId),
}

/// Gives the input kinds that `family` accepts, for `details.accepted`.
#[must_use]
pub const fn accepted(family: Family) -> &'static [&'static str] {
    match family {
        Family::Address => &[
            "address", "name", "fn:", "bb:", "op:", "imp:", "exp:", "str:", "jt:", "sec:", "seg:",
            "file:", "ext:",
        ],
        Family::Function => &[
            "address", "name", "fn:", "bb:", "op:", "imp:", "exp:", "jt:",
        ],
        Family::XrefTo => &[
            "address", "name", "fn:", "bb:", "op:", "imp:", "exp:", "sys:", "str:", "jt:", "ext:",
        ],
        Family::XrefFrom => &["address", "name", "fn:", "bb:", "op:", "exp:", "jt:"],
    }
}

/// Gives the target of `resolved` for `family`.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` with `details.accepted` for an input kind that the family does
/// not accept. Returns `NOT_IN_FUNCTION` for an address outside every function and
/// `ADDRESS_UNMAPPED` for an address that no region maps.
pub fn target(program: &Program, resolved: &Resolved, family: Family) -> Result<Target, ToolError> {
    target_at(program, resolved, family, &Site::default())
}

/// Gives the function that owns the mapped address `addr`.
fn owner(program: &Program, addr: Address, site: &Site<'_>) -> Result<FuncId, ToolError> {
    if !errors::mapped(program, addr) {
        return Err(errors::unmapped(program, addr, site));
    }
    program
        .owner_of(addr)
        .ok_or_else(|| errors::not_in_function(site))
}

/// Gives the target of `resolved` for `family`, with the field path of `site` in errors.
fn target_at(
    program: &Program,
    resolved: &Resolved,
    family: Family,
    site: &Site<'_>,
) -> Result<Target, ToolError> {
    let named = &resolved.named;
    let invalid = || errors::invalid_kind(family, site);
    match family {
        Family::Address => {
            let addr = value_at(program, resolved, site)?;
            if errors::mapped(program, addr) {
                Ok(Target::Addr(addr))
            } else {
                Err(errors::unmapped(program, addr, site))
            }
        }
        Family::Function => match named {
            Named::Addr(a) => owner(program, *a, site).map(Target::Func),
            Named::Func(f) => Ok(Target::Func(*f)),
            Named::Export(_) | Named::JumpTable(_) => {
                owner(program, value_at(program, resolved, site)?, site).map(Target::Func)
            }
            Named::Import(i) => super::import_entry(program, import_row(program, i, site)?)
                .and_then(|stub| program.owner_of(stub))
                .map(Target::Func)
                .ok_or_else(invalid),
            _ => Err(invalid()),
        },
        Family::XrefTo => match named {
            Named::Addr(_)
            | Named::Func(_)
            | Named::Export(_)
            | Named::Str(_)
            | Named::JumpTable(_)
            | Named::External(_) => value_at(program, resolved, site).map(Target::RefsTo),
            Named::Import(i) => Ok(Target::ImportSites(i.clone())),
            Named::Syscall(s) => Ok(Target::SyscallSites(s.clone())),
            Named::Region(_) | Named::Other(_) => Err(invalid()),
        },
        Family::XrefFrom => match named {
            Named::Addr(a) => Ok(Target::RefsFromInsn(*a)),
            Named::Func(f) => Ok(Target::RefsFromBody(*f)),
            Named::Export(_) => {
                owner(program, value_at(program, resolved, site)?, site).map(Target::RefsFromBody)
            }
            Named::JumpTable(j) => Ok(Target::CaseEdges(*j)),
            _ => Err(invalid()),
        },
    }
}

/// Gives the import row of `id`.
fn import_row<'p>(
    program: &'p Program,
    id: &ImportId,
    site: &Site<'_>,
) -> Result<&'p ImportRow, ToolError> {
    program.imports().get(id).ok_or_else(|| {
        let ids: Vec<String> = program.imports().keys().map(ToString::to_string).collect();
        errors::not_found(
            "import",
            &id.to_string(),
            ids.iter().map(String::as_str),
            site,
        )
    })
}

/// Gives the address of `resolved`, with the field path of `site` in errors.
fn value_at(program: &Program, resolved: &Resolved, site: &Site<'_>) -> Result<Address, ToolError> {
    match &resolved.named {
        Named::Addr(a) | Named::Region(a) | Named::External(a) => Ok(*a),
        Named::Func(f) => Ok(f.0),
        Named::Str(s) => Ok(s.0),
        Named::JumpTable(j) => Ok(j.0),
        Named::Import(i) => {
            let row = import_row(program, i, site)?;
            Ok(super::import_entry(program, row)
                .or(row.slot)
                .unwrap_or(row.ext))
        }
        Named::Export(e) => program
            .exports()
            .get(e)
            .and_then(|row| row.addr)
            .ok_or_else(|| errors::invalid("an export with an address", site)),
        Named::Syscall(_) | Named::Other(_) => Err(errors::invalid_kind(Family::Address, site)),
    }
}

/// Gives the address of `resolved` for the address family, with no map check.
///
/// `calc` uses it: an unmapped value is a valid number.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` with `details.accepted` for an input kind with no address.
pub fn value_of(program: &Program, resolved: &Resolved) -> Result<Address, ToolError> {
    value_at(program, resolved, &Site::default())
}

/// Resolves `input` for the address family: a mapped RAM address or an EXTERNAL address.
///
/// # Errors
///
/// Returns the errors of [`super::resolve`] and of [`target`].
pub fn address(
    program: &Program,
    input: &Value,
    site: &Site<'_>,
) -> Result<(Address, Resolved), ToolError> {
    let resolved = super::resolve(program, input, site)?;
    match target_at(program, &resolved, Family::Address, site)? {
        Target::Addr(addr) => Ok((addr, resolved)),
        _ => Err(errors::invalid_kind(Family::Address, site)),
    }
}

/// Resolves `input` for the function family.
///
/// # Errors
///
/// Returns the errors of [`super::resolve`] and of [`target`].
pub fn function(
    program: &Program,
    input: &Value,
    site: &Site<'_>,
) -> Result<(FuncId, Resolved), ToolError> {
    let resolved = super::resolve(program, input, site)?;
    match target_at(program, &resolved, Family::Function, site)? {
        Target::Func(func) => Ok((func, resolved)),
        _ => Err(errors::invalid_kind(Family::Function, site)),
    }
}
