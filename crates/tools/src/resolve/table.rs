//! The target table (design Section 10.5): what each input kind means to each tool family.
//!
//! | Input kind | [`Family::Address`] | [`Family::Function`] | [`Family::XrefTo`] | [`Family::XrefFrom`] |
//! |---|---|---|---|---|
//! | address, name, `bb:`, `op:` | that address | the owner function, else `NOT_IN_FUNCTION` | refs to the address | refs from the one instruction |
//! | `fn:F`, `exp:F` | the entry of F | F | refs to the entry | refs from the body of F |
//! | `imp:X` | the stub, else the slot, else the EXTERNAL address | the stub function, else invalid | the sites of the import | invalid |
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
use ghidorah_db::Program;
use ghidorah_json::Value;

use super::{Resolved, Site};
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
    let _ = family;
    &[]
}

/// Gives the target of `resolved` for `family`.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` with `details.accepted` for an input kind that the family does
/// not accept, `NOT_IN_FUNCTION` for an address outside every function and `ADDRESS_UNMAPPED`
/// for an unmapped address of the address family.
pub fn target(program: &Program, resolved: &Resolved, family: Family) -> Result<Target, ToolError> {
    let _ = (program, resolved, family);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
}

/// Gives the address of `resolved` for the address family, with no map check.
///
/// `calc` uses it: an unmapped value is a valid number.
///
/// # Errors
///
/// Returns `INVALID_ARGUMENT` with `details.accepted` for an input kind with no address.
pub fn value_of(program: &Program, resolved: &Resolved) -> Result<Address, ToolError> {
    let _ = (program, resolved);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
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
    let _ = (program, input, site);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
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
    let _ = (program, input, site);
    Err(ToolError::new(ghidorah_base::ErrorCode::InternalError))
}
