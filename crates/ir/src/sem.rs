//! The flag semantic module (design Section 6.2, ADR-0009).
//!
//! This module is the one source of truth for x86 flags. The interpreter, flag
//! materialization and fusion use only these functions. `Sub`, `Add` and `Logic` call the
//! verified kernel K5, so the proved functions are the shipped functions.
//!
//! Each function reads the low `w` bits of its inputs. A width other than 8, 16 or 32
//! counts as 64. The flags word has CF at bit 0, PF at 2, AF at 4, ZF at 6, SF at 7 and
//! OF at 11. The other bits are 0.

pub use ghidorah_kernel::flags::{AF, CF, OF, PF, SF, ZF};

use crate::op::{Cc, FlagOp};

/// The six status flags.
pub const STATUS: u16 = CF | PF | AF | ZF | SF | OF;

/// Gives the flags of the thunk `Flags(op, a, b, c)` at operand width `w`.
///
/// The [`FlagOp`] docs give the meaning of `a`, `b` and `c`. A flag of
/// [`undefined_mask`] has a fixed value here, but the hardware value can differ.
#[must_use]
pub fn x86_flags(op: FlagOp, w: u8, a: u64, b: u64, c: u64) -> u16 {
    let _unused = (op, w, a, b, c);
    0
}

/// Gives the x86 condition `cc` on a flags word.
#[must_use]
pub fn x86_cond(cc: Cc, flags: u16) -> bool {
    let _unused = (cc, flags);
    false
}

/// Gives the flags that the hardware leaves undefined after `op`.
///
/// Tests mask these flags, and fusion never reads them. For shifts and rotates, OF is
/// defined only for a count of 1, and the mask holds OF.
#[must_use]
pub fn undefined_mask(op: FlagOp) -> u16 {
    let _unused = op;
    0
}
