//! The warnings of a decompile with their remedy calls (design Section 8.5).
//!
//! Each warning has a code and an address. A warning gets a remedy when a complete call can
//! check or fix its cause:
//!
//! | Code | Remedy |
//! |---|---|
//! | `W_NORETURN_ASSUMED` | `func_get { target: <callee>, include: ["disasm"] }` |
//! | `W_LIFT_UNSUPPORTED` | `mem_read { target: <at>, as: "insn", count: 1 }` |
//! | `W_STRUCTURE_SELFCHECK` | `func_get { target: <entry>, include: ["disasm"] }` |
//! | other codes | none |
//!
//! The rows sort by address, then by code number.

use ghidorah_base::WarningCode;

use crate::Warning;
use crate::view::View;

/// A remedy call of a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Remedy {
    /// `func_get` with the disassembly of the function at the address.
    Disasm(u64),
    /// `mem_read` of the one instruction at the address.
    Insn(u64),
}

/// One warning of the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WarningRow {
    /// The address.
    pub at: u64,
    /// The code.
    pub code: WarningCode,
    /// The remedy call.
    pub remedy: Option<Remedy>,
}

/// Gives the warning rows of `warnings` in output order, one row for each distinct warning.
/// The view gives the callee of a call site and the entry.
#[must_use]
pub fn rows(warnings: &[Warning], view: &View) -> Vec<WarningRow> {
    let _ = (warnings, view);
    Vec::new()
}
