//! K7: the provenance write rule (design Section 3.6, ADR-0013).
//!
//! Each fact has a source rank. A write over a fact succeeds when the new rank is not lower.
//! An `Agent` write over an `Imported` fact succeeds only with `force`.
//! Verus proves that [`may_overwrite`] equals this rule for all inputs.

#[cfg(not(verus_only))]
use ghidorah_spec::{verus_spec, verus_verify};
#[cfg(verus_only)]
use vstd::prelude::*;

/// The rank of a computed default. The DB never stores a default name.
#[verus_verify]
pub const DEFAULT: u8 = 1;

/// The rank of a fact from an analyzer.
#[verus_verify]
pub const ANALYSIS: u8 = 2;

/// The rank of a fact from an MCP or CLI call.
#[verus_verify]
pub const AGENT: u8 = 3;

/// The rank of a fact from a symbol table, a relocation or a PLT name.
#[verus_verify]
pub const IMPORTED: u8 = 4;

/// The rank of a fact from `ghidorah call --source user`.
#[verus_verify]
pub const USER: u8 = 5;

/// Tells if a write of rank `new_rank` can replace a fact of rank `old_rank`.
///
/// The write succeeds when `new_rank >= old_rank`.
/// An [`AGENT`] write over an [`IMPORTED`] fact also succeeds with `force`.
///
/// Verus proves the rule and three properties of the order that do not copy the rule:
///
/// - The result is monotone in `new_rank`: it is a threshold that `old_rank` and `force` set.
/// - `force` changes the result only for an [`AGENT`] write over an [`IMPORTED`] fact.
/// - On the ranks 1 to 5, a [`USER`] write and a write over a [`DEFAULT`] fact always succeed.
///   A [`DEFAULT`] write succeeds only over a [`DEFAULT`] fact.
#[must_use]
#[verus_spec(r =>
    ensures
        r == (new_rank >= old_rank || (old_rank == IMPORTED && new_rank == AGENT && force)),
        r == (new_rank >= if old_rank == IMPORTED && force { AGENT } else { old_rank }),
        !(old_rank == IMPORTED && new_rank == AGENT) ==> r == (new_rank >= old_rank),
        DEFAULT <= old_rank <= USER && DEFAULT <= new_rank <= USER ==> {
            &&& new_rank == USER ==> r
            &&& old_rank == DEFAULT ==> r
            &&& new_rank == DEFAULT ==> (r <==> old_rank == DEFAULT)
        },
)]
pub fn may_overwrite(old_rank: u8, new_rank: u8, force: bool) -> bool {
    new_rank >= old_rank || (old_rank == IMPORTED && new_rank == AGENT && force)
}
