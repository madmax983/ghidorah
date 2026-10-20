//! The remedy calls of the warnings of `func_get` (design Sections 8.5 and 10.8).
//!
//! Each remedy is a complete call `{ tool, args, why }`. A remedy that `hints::check` does
//! not accept goes, so a result never holds a call that the agent cannot send.
//!
//! | Code | Remedy |
//! |---|---|
//! | `W_JUMPTABLE_UNRESOLVED`, a table of function entries or an import slot | `func_edit { action: "set_call_targets", at, targets }` |
//! | `W_JUMPTABLE_UNRESOLVED`, a table of instructions of the function | `func_edit { action: "set_jumptable", at, targets }` |
//! | `W_INDIRECT_CALL_UNRESOLVED`, a table of function entries or an import slot | `func_edit { action: "set_call_targets", at, targets }` |
//! | other codes | none |
//!
//! The table of a site is the jump-table record base. Else it is the target of the nearest
//! data reference from the site or from one of the [`BACK`] instructions before it in the
//! function. The targets are the 8-byte entries of the table from its start, at most
//! [`MAX_ENTRIES`]. The list stops at the first entry of another kind.

use ghidorah_base::{Address, FuncId, JumpTableId, Limits};
use ghidorah_db::{Program, RefType};
use ghidorah_json::Value;

use crate::api::Host;
use crate::handlers::func_sections as fs;
use crate::hints::{self, Call};
use crate::session::Session;

/// The most instructions before a site that the table search reads.
pub const BACK: usize = 8;

/// The most entries of a table that a remedy reads.
pub const MAX_ENTRIES: u64 = 64;

/// The `why` of a `set_call_targets` remedy.
pub const WHY_CALL_TARGETS: &str =
    "Set the targets of the indirect jump or call. Make sure that each target is correct.";

/// The `why` of a `set_jumptable` remedy.
pub const WHY_JUMPTABLE: &str =
    "Set the cases of the jump table. Make sure that each case is correct.";

/// Every fixed text of the remedies that an agent reads.
pub const TEXTS: &[&str] = &[WHY_CALL_TARGETS, WHY_JUMPTABLE];

/// Keeps `call` when `hints::check` accepts it in the active registry and profile of
/// `session`.
#[must_use]
pub fn checked(session: &Session, call: Call) -> Option<Call> {
    let registry = session.active_registry();
    hints::check(&registry, &|name| session.in_profile(name), &call)
        .is_ok()
        .then_some(call)
}

/// Gives the table of the site `at` of `func`. It is the base of the jump-table record of the
/// site. Else it is the target of the nearest data reference from the site or the
/// instructions before it.
fn table_of(p: &Program, func: FuncId, at: u64) -> Option<u64> {
    if let Some(base) = p
        .jump_table(JumpTableId(Address::ram(at)))
        .and_then(|t| t.value.base)
    {
        return Some(base.off);
    }
    let units = fs::body_units(p, func);
    let data = |site: u64| {
        p.refs_from(Address::ram(site))
            .into_iter()
            .map(|r| r.value.key)
            .find(|k| matches!(k.kind, RefType::Data | RefType::Read) && k.to.is_ram())
            .map(|k| k.to.off)
    };
    units
        .iter()
        .rev()
        .filter(|(site, _)| *site <= at)
        .take(BACK.saturating_add(1))
        .find_map(|(site, _)| data(*site))
}

/// Gives the 8-byte entries of the table at `base`, at most [`MAX_ENTRIES`].
fn entries(p: &Program, base: u64) -> Vec<u64> {
    let mut out = Vec::new();
    for k in 0..MAX_ENTRIES {
        let Some(addr) = k.checked_mul(8).and_then(|off| base.checked_add(off)) else {
            break;
        };
        let Ok(bytes) = p.mem().read(addr, 8, &Limits::DEFAULT) else {
            break;
        };
        let Ok(word) = <[u8; 8]>::try_from(&*bytes) else {
            break;
        };
        out.push(u64::from_le_bytes(word));
    }
    out
}

/// Gives the `func_edit` call `action` at `at` with `targets`.
fn site_call(action: &str, at: u64, targets: Vec<Value>, why: &str) -> Call {
    Call::new(
        "func_edit",
        Value::object([
            ("action", Value::from(action)),
            ("at", fs::hex(at)),
            ("targets", Value::Array(targets)),
        ]),
        why,
    )
}

/// Gives the remedy of the unresolved indirect jump or call at `at` of `func`.
///
/// A jump also takes a table of instructions of the function as a jump table. Gives `None`
/// when the site has no table with targets.
#[must_use]
pub fn site(p: &Program, func: FuncId, at: u64, jump: bool) -> Option<Call> {
    let base = table_of(p, func, at)?;
    if let Some(row) = p
        .imports()
        .values()
        .find(|r| r.slot == Some(Address::ram(base)))
    {
        let target = Value::from(row.id.to_string());
        return Some(site_call(
            "set_call_targets",
            at,
            vec![target],
            WHY_CALL_TARGETS,
        ));
    }
    let words = entries(p, base);
    let funcs: Vec<Value> = words
        .iter()
        .map_while(|w| {
            let id = FuncId(Address::ram(*w));
            p.func(id).map(|_| Value::from(id.to_string()))
        })
        .collect();
    if !funcs.is_empty() {
        return Some(site_call("set_call_targets", at, funcs, WHY_CALL_TARGETS));
    }
    if !jump {
        return None;
    }
    let units = fs::body_units(p, func);
    let cases: Vec<Value> = words
        .iter()
        .map_while(|w| {
            units
                .binary_search_by_key(w, |u| u.0)
                .ok()
                .map(|_| fs::hex(*w))
        })
        .collect();
    (!cases.is_empty()).then(|| site_call("set_jumptable", at, cases, WHY_JUMPTABLE))
}
