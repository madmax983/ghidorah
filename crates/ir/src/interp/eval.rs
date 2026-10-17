//! The data ops of the interpreter: one pure function from inputs to a result.
//!
//! Each input reads its low `w` bits, except where the op table of [`crate::op`] gives
//! another width. Signed ops read bit `w - 1` as the sign.

use super::EvalError;
use crate::op::{Cc, FlagOp, Opc};
use crate::sem::{STATUS, x86_cond, x86_flags};

/// The value mask of a width from 1 to 128.
pub(crate) const fn mask(w: u8) -> u128 {
    if w >= 128 {
        u128::MAX
    } else {
        (1u128 << w) - 1
    }
}

/// The bits of a `u128` as an `i128`.
const fn to_i(x: u128) -> i128 {
    x.cast_signed()
}

/// The bits of an `i128` as a `u128`.
const fn to_u(x: i128) -> u128 {
    x.cast_unsigned()
}

/// The signed value of the low `w` bits, for `w` from 1 to 128.
fn sext(x: u128, w: u8) -> i128 {
    let shift = 128u32.saturating_sub(u32::from(w));
    to_i(x << shift) >> shift
}

/// Gives the low 64 bits of a value.
pub(crate) fn low64(x: u128) -> u64 {
    u64::try_from(x & u128::from(u64::MAX)).unwrap_or(u64::MAX)
}

/// Gives the low 16 bits of a value.
fn low16(x: u128) -> u16 {
    u16::try_from(x & 0xffff).unwrap_or(u16::MAX)
}

/// Gives the full 256-bit product `(high, low)` of two `u128` values.
const fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const LOW: u128 = 0xffff_ffff_ffff_ffff;
    let (a0, a1) = (a & LOW, a >> 64);
    let (b0, b1) = (b & LOW, b >> 64);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & LOW) + (p10 & LOW);
    let low = (p00 & LOW) | (mid << 64);
    let high = p11
        .wrapping_add(p01 >> 64)
        .wrapping_add(p10 >> 64)
        .wrapping_add(mid >> 64);
    (high, low)
}

/// Gives bits `w..2w` of a 256-bit product.
fn high_part(high: u128, low: u128, w: u8) -> u128 {
    if w >= 128 {
        high & mask(w)
    } else {
        ((high << (128 - u32::from(w))) | (low >> w)) & mask(w)
    }
}

/// Gives the high half of the product of two `w`-bit values.
fn mul_high(x: u128, y: u128, w: u8, signed: bool) -> u128 {
    if !signed {
        let (high, low) = mul_wide(x, y);
        return high_part(high, low, w);
    }
    let (sx, sy) = (to_u(sext(x, w)), to_u(sext(y, w)));
    let (high, low) = mul_wide(sx, sy);
    // The signed high half of the 128-bit operands: subtract `y` and `x` for each sign.
    let mut high = high;
    if sext(x, w) < 0 {
        high = high.wrapping_sub(sy);
    }
    if sext(y, w) < 0 {
        high = high.wrapping_sub(sx);
    }
    high_part(high, low, w)
}

/// Gives a rotation of the low `w` bits by `n` modulo `w`.
fn rotate(value: u128, cnt: u128, w: u8, left: bool) -> u128 {
    let turn = u32::try_from(cnt % u128::from(w)).unwrap_or(0);
    if turn == 0 {
        return value;
    }
    let wide = u32::from(w);
    let (up, down) = if left {
        (turn, wide - turn)
    } else {
        (wide - turn, turn)
    };
    ((value << up) | (value >> down)) & mask(w)
}

/// Gives a shift count below `w`, or `None` for a count of `w` or more.
fn small_count(n: u128, w: u8) -> Option<u32> {
    if n < u128::from(w) {
        u32::try_from(n).ok()
    } else {
        None
    }
}

/// Gives the result of a data op. [`super::eval`] gives the contract.
pub(super) fn eval(opc: Opc, w: u8, sub: u8, x: u128, y: u128, z: u128) -> Result<u128, EvalError> {
    if !is_data(opc) {
        return Err(EvalError::NotData);
    }
    if w == 0 || w > 128 {
        return Err(EvalError::BadWidth);
    }
    let low = mask(w);
    let (xm, ym) = (x & low, y & low);
    let res = match opc {
        Opc::Copy | Opc::Trunc => xm,
        Opc::Add => xm.wrapping_add(ym),
        Opc::Sub => xm.wrapping_sub(ym),
        Opc::Mul => xm.wrapping_mul(ym),
        Opc::UMulHi => mul_high(xm, ym, w, false),
        Opc::SMulHi => mul_high(xm, ym, w, true),
        Opc::UDiv => xm.checked_div(ym).ok_or(EvalError::DivZero)?,
        Opc::URem => xm.checked_rem(ym).ok_or(EvalError::DivZero)?,
        Opc::SDiv | Opc::SRem => signed_div(opc, xm, ym, w)?,
        Opc::Neg => xm.wrapping_neg(),
        Opc::Not => !xm,
        Opc::And => xm & ym,
        Opc::Or => xm | ym,
        Opc::Xor => xm ^ ym,
        Opc::Shl => small_count(y, w).map_or(0, |n| xm << n),
        Opc::LShr => small_count(y, w).map_or(0, |n| xm >> n),
        Opc::AShr => {
            let cnt = small_count(y, w).unwrap_or_else(|| u32::from(w) - 1);
            to_u(sext(xm, w) >> cnt)
        }
        Opc::Rol => rotate(xm, y, w, true),
        Opc::Ror => rotate(xm, y, w, false),
        Opc::ZExt | Opc::SExt => extend(opc, x, w, sub)?,
        Opc::Extract => small_count(y, 128).map_or(0, |lo| x >> lo),
        Opc::Insert => insert(xm, y, z, w, sub)?,
        Opc::Popcnt => u128::from(xm.count_ones()),
        Opc::Clz => u128::from(xm.leading_zeros() - (128 - u32::from(w))),
        Opc::Ctz => u128::from(xm.trailing_zeros().min(u32::from(w))),
        Opc::Bswap if w.is_multiple_of(8) => xm.swap_bytes() >> (128 - u32::from(w)),
        Opc::Bswap => return Err(EvalError::BadWidth),
        Opc::Eq => u128::from(xm == ym),
        Opc::Ne => u128::from(xm != ym),
        Opc::ULt => u128::from(xm < ym),
        Opc::ULe => u128::from(xm <= ym),
        Opc::SLt => u128::from(sext(xm, w) < sext(ym, w)),
        Opc::SLe => u128::from(sext(xm, w) <= sext(ym, w)),
        Opc::TestZ => u128::from(xm & ym == 0),
        Opc::TestNZ => u128::from(xm & ym != 0),
        Opc::Ite => {
            if x == 0 {
                z
            } else {
                y
            }
        }
        Opc::Flags => return flags(x, y, z, w, sub),
        Opc::Cond => {
            let cc = Cc::x86(sub).ok_or(EvalError::BadWidth)?;
            u128::from(x86_cond(cc, low16(x)))
        }
        Opc::FlagsSel => {
            if x == 0 {
                z & 0xffff
            } else {
                y & 0xffff
            }
        }
        Opc::FlagsGet => x & 0xffff,
        Opc::FlagsSet => x & u128::from(STATUS),
        _ => return Err(EvalError::NotData),
    };
    Ok(res & low)
}

/// Tells if `opc` is a data op.
const fn is_data(opc: Opc) -> bool {
    !matches!(
        opc,
        Opc::Get
            | Opc::Put
            | Opc::Load
            | Opc::Store
            | Opc::Jump
            | Opc::CJump
            | Opc::JumpInd
            | Opc::Call
            | Opc::CallInd
            | Opc::Ret
            | Opc::Syscall
            | Opc::Intrinsic
            | Opc::Unimpl
            | Opc::Nop
            | Opc::Phi
    )
}

/// Gives `SDiv` or `SRem`, rounded to zero. The minimum divided by -1 wraps.
fn signed_div(opc: Opc, x: u128, y: u128, w: u8) -> Result<u128, EvalError> {
    let (sx, sy) = (sext(x, w), sext(y, w));
    if sy == 0 {
        return Err(EvalError::DivZero);
    }
    Ok(to_u(if opc == Opc::SDiv {
        sx.wrapping_div(sy)
    } else {
        sx.wrapping_rem(sy)
    }))
}

/// Gives `ZExt` or `SExt` of the low `from` bits to `w` bits.
fn extend(opc: Opc, x: u128, w: u8, from: u8) -> Result<u128, EvalError> {
    if from == 0 || from > w {
        return Err(EvalError::BadWidth);
    }
    let x = x & mask(from);
    Ok(if opc == Opc::SExt {
        to_u(sext(x, from))
    } else {
        x
    })
}

/// Gives `Insert`: the low `part_w` bits of `part` replace the bits from `lo` of `base`.
fn insert(base: u128, part: u128, lo: u128, w: u8, part_w: u8) -> Result<u128, EvalError> {
    let lo = small_count(lo, w).ok_or(EvalError::BadWidth)?;
    if part_w == 0 || u32::from(part_w) + lo > u32::from(w) {
        return Err(EvalError::BadWidth);
    }
    let field = mask(part_w) << lo;
    Ok((base & !field) | ((part << lo) & field))
}

/// Gives the flags word of a `Flags` op at operand width `w`.
fn flags(a: u128, b: u128, c: u128, w: u8, sub: u8) -> Result<u128, EvalError> {
    let op = FlagOp::from_code(sub).ok_or(EvalError::BadWidth)?;
    if !matches!(w, 8 | 16 | 32 | 64) {
        return Err(EvalError::BadWidth);
    }
    Ok(u128::from(x86_flags(op, w, low64(a), low64(b), low64(c))))
}
