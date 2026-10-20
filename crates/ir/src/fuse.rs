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
//! The `Add` row compares `a` with `-b` at the width of the `Flags` op, so it needs a
//! constant `b`. Each other flag operation gives `None`. An undefined flag never feeds fusion.

pub use ghidorah_kernel::flags::Pred;
use ghidorah_kernel::flags::{FuseOp, fused_pred, fused_rhs};

use crate::op::{Arg, Cc, FlagOp, Opc};

/// Gives the compare op of `p`: `(opc, x, y)` for the arguments `a` and `b`.
///
/// `UGt`, `UGe`, `SGt` and `SGe` swap the arguments.
#[must_use]
pub const fn pred_opc(p: Pred, a: Arg, b: Arg) -> (Opc, Arg, Arg) {
    match p {
        Pred::Eq => (Opc::Eq, a, b),
        Pred::Ne => (Opc::Ne, a, b),
        Pred::ULt => (Opc::ULt, a, b),
        Pred::ULe => (Opc::ULe, a, b),
        Pred::UGt => (Opc::ULt, b, a),
        Pred::UGe => (Opc::ULe, b, a),
        Pred::SLt => (Opc::SLt, a, b),
        Pred::SLe => (Opc::SLe, a, b),
        Pred::SGt => (Opc::SLt, b, a),
        Pred::SGe => (Opc::SLe, b, a),
        Pred::TestZ => (Opc::TestZ, a, b),
        Pred::TestNZ => (Opc::TestNZ, a, b),
    }
}

/// Tells if the x86 condition `code` reads CF: B, AE, BE and A.
const fn reads_cf(code: u8) -> bool {
    matches!(code, 2 | 3 | 6 | 7)
}

/// Gives the compare that `Cond(cc, Flags(op, a, b, _))` fuses into, or `None`. `w` is the
/// width of the `Flags` op.
///
/// The compare op takes the width `w`. The `Add` row gives the constant `-b` at the width
/// `w`, the right operand of the K5 proof. A width that is not 8, 16 or 32 bits gives the
/// constant at 64 bits.
#[must_use]
pub fn fuse(op: FlagOp, cc: Cc, w: u8, a: Arg, b: Arg) -> Option<(Opc, Arg, Arg)> {
    let code = cc.code();
    let (row, lhs, rhs) = match op {
        FlagOp::X86Sub => (FuseOp::Sub, a, b),
        FlagOp::X86Add => (FuseOp::Add, a, b),
        FlagOp::X86Logic => (FuseOp::Logic, a, b),
        FlagOp::X86Neg => (FuseOp::Sub, Arg::k(0), a),
        FlagOp::X86Dec if !reads_cf(code) => (FuseOp::Sub, a, Arg::k(1)),
        FlagOp::X86Inc if !reads_cf(code) => (FuseOp::Add, a, Arg::k(1)),
        _ => return None,
    };
    let pred = fused_pred(row, code)?;
    let rhs = match row {
        FuseOp::Add => Arg::k(fused_rhs(FuseOp::Add, rhs.as_k()?, u32::from(w))),
        FuseOp::Sub | FuseOp::Logic => rhs,
    };
    Some(pred_opc(pred, lhs, rhs))
}
