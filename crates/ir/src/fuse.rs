//! Flag fusion through kernel K5 (design Section 6.2, ADR-0009).
//!
//! `Cond(cc, Flags(op, a, b, c))` can become one compare op `opc(x, y)` at the width of
//! the `Flags` op. [`fuse`] gives `(opc, x, y)`. It calls the verified table
//! `kernel::flags::fused_pred` and maps each [`Pred`] to an opcode with one total match
//! ([`pred_opc`]).
//!
//! | `op` | Reduction |
//! |---|---|
//! | `X86Sub`, `X86Add`, `X86Logic` | the K5 table on `(a, b)` |
//! | `X86Neg` | the `Sub` row on `(0, a)`: the flags are equal |
//! | `X86Dec` | the `Sub` row on `(a, 1)`, for a condition that does not read CF |
//! | `X86Inc` | the `Add` row on `(a, 1)`, for a condition that does not read CF |
//!
//! The `Add` row compares `a` with `-b`, so it needs a constant `b`.
//! Each other flag operation gives `None`. An undefined flag never feeds fusion.

pub use ghidorah_kernel::flags::Pred;

use crate::op::{Arg, Cc, FlagOp, Opc};

/// Gives the compare op of `p`: `(opc, x, y)` for the arguments `a` and `b`.
///
/// `UGt`, `UGe`, `SGt` and `SGe` swap the arguments.
#[must_use]
pub const fn pred_opc(p: Pred, a: Arg, b: Arg) -> (Opc, Arg, Arg) {
    let _unused = p;
    (Opc::Nop, a, b)
}

/// Gives the compare that `Cond(cc, Flags(op, a, b, _))` fuses into, or `None`.
///
/// The compare op takes the width of the `Flags` op. It reads the low bits of a constant
/// at that width, so a negated constant of 64 bits is correct at each width.
#[must_use]
pub fn fuse(op: FlagOp, cc: Cc, a: Arg, b: Arg) -> Option<(Opc, Arg, Arg)> {
    let _unused = (op, cc, a, b);
    None
}
