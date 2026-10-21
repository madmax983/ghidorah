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
//! | `W_JUMPTABLE_UNRESOLVED` | `func_edit { action: "set_jumptable", at }`, or `set_call_targets` when the table holds function entries |
//! | `W_INDIRECT_CALL_UNRESOLVED` | `func_edit { action: "set_call_targets", at }` |
//! | other codes | none |
//!
//! The `func_edit` remedies need the `targets` of the site. The tools crate reads them from
//! the table of the site, and it drops a remedy with no targets.
//!
//! The rows sort by address, then by code number.

use ghidorah_base::WarningCode;

use crate::Warning;
use crate::expr::{Callee, Stmt};
use crate::view::View;

/// A remedy call of a warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Remedy {
    /// `func_get` with the disassembly of the function at the address.
    Disasm(u64),
    /// `mem_read` of the one instruction at the address.
    Insn(u64),
    /// `func_edit` with the cases of the unresolved jump at the address: `set_jumptable`, or
    /// `set_call_targets` for a table of function entries.
    JumpTable(u64),
    /// `func_edit { action: "set_call_targets" }` of the indirect call at the address.
    CallTargets(u64),
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
    let mut out: Vec<WarningRow> = warnings
        .iter()
        .map(|w| WarningRow {
            at: w.at,
            code: w.code,
            remedy: remedy(w, view),
        })
        .collect();
    out.sort_unstable_by_key(|r| (r.at, r.code.num()));
    out.dedup_by_key(|r| (r.at, r.code));
    out
}

/// Gives the remedy of one warning.
fn remedy(w: &Warning, view: &View) -> Option<Remedy> {
    match w.code {
        WarningCode::NoreturnAssumed => callee_at(view, w.at).map(Remedy::Disasm),
        WarningCode::LiftUnsupported => Some(Remedy::Insn(w.at)),
        WarningCode::StructureSelfcheck => Some(Remedy::Disasm(view.entry)),
        WarningCode::JumptableUnresolved => Some(Remedy::JumpTable(w.at)),
        WarningCode::IndirectCallUnresolved => Some(Remedy::CallTargets(w.at)),
        _ => None,
    }
}

/// Gives the target of the direct call at the instruction `at`.
fn callee_at(view: &View, at: u64) -> Option<u64> {
    view.nodes
        .iter()
        .flat_map(|n| &n.stmts)
        .find_map(|s| match s {
            Stmt::Call(c) if c.at.addr == at => match c.callee {
                Callee::Direct(t) => Some(t),
                _ => None,
            },
            _ => None,
        })
}
