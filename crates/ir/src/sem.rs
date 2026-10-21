//! The flag semantic module (design Section 6.2, ADR-0009).
//!
//! This module is the one source of truth for x86 flags. The interpreter, flag
//! materialization and fusion use only these functions. `Sub`, `Add`, `Logic`, `Inc`,
//! `Dec` and `Neg` use the verified kernel K5, so the proved functions are the shipped
//! functions.
//!
//! Each function reads the low `w` bits of its inputs. A width other than 8, 16 or 32
//! counts as 64. The flags word has CF at bit 0, PF at 2, AF at 4, ZF at 6, SF at 7 and
//! OF at 11. The other bits are 0. An undefined flag has the value 0, or the value that
//! the table gives.

pub use ghidorah_kernel::flags::{AF, CF, OF, PF, SF, ZF};
use ghidorah_kernel::flags::{x86_add_flags, x86_logic_flags, x86_sub_flags};

use crate::op::{Cc, FlagOp};

/// The six status flags.
pub const STATUS: u16 = CF | PF | AF | ZF | SF | OF;

/// The width of a flag operation: 8, 16, 32 or 64.
const fn canonical(w: u8) -> u32 {
    match w {
        8 => 8,
        16 => 16,
        32 => 32,
        _ => 64,
    }
}

/// The value mask of a canonical width.
const fn mask(w: u32) -> u64 {
    if w >= 64 { u64::MAX } else { (1 << w) - 1 }
}

/// Gives `bit` when `set` is true, else 0.
const fn flag(set: bool, bit: u16) -> u16 {
    if set { bit } else { 0 }
}

/// Gives ZF, SF and PF of a result at width `width`.
const fn result_flags(res: u64, width: u32) -> u16 {
    flag(res == 0, ZF)
        | flag((res >> (width - 1)) & 1 == 1, SF)
        | flag((res & 0xff).count_ones().is_multiple_of(2), PF)
}

/// Gives the low 16 bits of a value.
fn low16(v: u64) -> u16 {
    u16::try_from(v & 0xffff).unwrap_or(u16::MAX)
}

/// Gives the signed value of the low `width` bits.
const fn signed(value: u64, width: u32) -> i64 {
    let shift = 64 - width;
    ((value << shift).cast_signed()) >> shift
}

/// Gives the flags of the thunk `Flags(op, a, b, c)` at operand width `w`.
///
/// The [`FlagOp`] docs give the meaning of `a`, `b` and `c`. A shift or rotate masks its
/// count to 5 bits (6 bits at width 64). A masked count of 0 keeps the old flags `c`.
/// A flag of [`undefined_mask`] has a fixed value here, but the hardware value can differ.
#[must_use]
pub fn x86_flags(op: FlagOp, w: u8, a: u64, b: u64, c: u64) -> u16 {
    let width = canonical(w);
    let low = mask(width);
    let (lhs, rhs) = (a & low, b & low);
    let old = low16(c) & STATUS;
    match op {
        FlagOp::X86Add => x86_add_flags(lhs, rhs, width),
        FlagOp::X86Sub => x86_sub_flags(lhs, rhs, width),
        FlagOp::X86Logic => x86_logic_flags(lhs, rhs, width),
        FlagOp::X86Adc => carry_flags(lhs, rhs, c & 1, width, false),
        FlagOp::X86Sbb => carry_flags(lhs, rhs, c & 1, width, true),
        FlagOp::X86Inc => (x86_add_flags(lhs, 1, width) & !CF) | (old & CF),
        FlagOp::X86Dec => (x86_sub_flags(lhs, 1, width) & !CF) | (old & CF),
        FlagOp::X86Neg => x86_sub_flags(0, lhs, width),
        FlagOp::X86Shl | FlagOp::X86Shr | FlagOp::X86Sar => shift_flags(op, lhs, b, old, width),
        FlagOp::X86Rol | FlagOp::X86Ror => rotate_flags(op, lhs, b, old, width),
        FlagOp::X86UMul => {
            let high = (u128::from(lhs) * u128::from(rhs)) >> width;
            flag(high != 0, CF | OF)
        }
        FlagOp::X86SMul => {
            let product = i128::from(signed(lhs, width)) * i128::from(signed(rhs, width));
            let half = 1i128 << (width - 1);
            flag(product < -half || product >= half, CF | OF)
        }
        FlagOp::X86Bt => {
            let bit = (lhs >> (b % u64::from(width))) & 1;
            flag(bit == 1, CF) | (old & ZF)
        }
        FlagOp::Copy => low16(a) & STATUS,
    }
}

/// Gives the flags of `adc` (`borrow` is false) or `sbb` with the carry `cin`.
fn carry_flags(lhs: u64, rhs: u64, cin: u64, width: u32, borrow: bool) -> u16 {
    let low = mask(width);
    let top = 1u64 << (width - 1);
    let (res, cf, of) = if borrow {
        let res = lhs.wrapping_sub(rhs).wrapping_sub(cin) & low;
        let cf = u128::from(lhs) < u128::from(rhs) + u128::from(cin);
        (res, cf, (lhs ^ rhs) & (lhs ^ res) & top != 0)
    } else {
        let full = u128::from(lhs) + u128::from(rhs) + u128::from(cin);
        let res = lhs.wrapping_add(rhs).wrapping_add(cin) & low;
        (
            res,
            full > u128::from(low),
            (lhs ^ res) & (rhs ^ res) & top != 0,
        )
    };
    flag(cf, CF) | flag((lhs ^ rhs ^ res) & 0x10 != 0, AF) | flag(of, OF) | result_flags(res, width)
}

/// Gives the masked count of a shift or rotate.
const fn count(b: u64, width: u32) -> u64 {
    if width == 64 { b & 63 } else { b & 31 }
}

/// Gives the flags of `shl`, `shr` or `sar`. AF is 0.
fn shift_flags(op: FlagOp, value: u64, b: u64, old: u16, width: u32) -> u16 {
    let cnt = count(b, width);
    if cnt == 0 {
        return old;
    }
    let wide = u64::from(width);
    let low = mask(width);
    let sign = (value >> (width - 1)) & 1;
    let (res, cf, of) = match op {
        FlagOp::X86Shl => {
            let res = if cnt >= wide { 0 } else { (value << cnt) & low };
            let cf = if cnt <= wide {
                (value >> (wide - cnt)) & 1
            } else {
                0
            };
            (res, cf, ((res >> (width - 1)) & 1) ^ cf)
        }
        FlagOp::X86Shr => {
            let res = if cnt >= wide { 0 } else { value >> cnt };
            let cf = if cnt <= wide {
                (value >> (cnt - 1)) & 1
            } else {
                0
            };
            (res, cf, sign)
        }
        _ => {
            let res = if cnt >= wide {
                if sign == 1 { low } else { 0 }
            } else {
                (signed(value, width) >> cnt).cast_unsigned() & low
            };
            let cf = if cnt >= wide {
                sign
            } else {
                (value >> (cnt - 1)) & 1
            };
            (res, cf, 0)
        }
    };
    flag(cf == 1, CF) | flag(of == 1, OF) | result_flags(res, width)
}

/// Gives the flags of `rol` or `ror`. Only CF and OF change.
fn rotate_flags(op: FlagOp, value: u64, b: u64, old: u16, width: u32) -> u16 {
    let cnt = count(b, width);
    if cnt == 0 {
        return old;
    }
    let low = mask(width);
    let turn = u32::try_from(cnt % u64::from(width)).unwrap_or(0);
    let res = if turn == 0 {
        value
    } else if op == FlagOp::X86Rol {
        ((value << turn) | (value >> (width - turn))) & low
    } else {
        ((value >> turn) | (value << (width - turn))) & low
    };
    let top = (res >> (width - 1)) & 1;
    let (cf, of) = if op == FlagOp::X86Rol {
        let cf = res & 1;
        (cf, top ^ cf)
    } else {
        (top, top ^ ((res >> (width - 2)) & 1))
    };
    (old & !(CF | OF)) | flag(cf == 1, CF) | flag(of == 1, OF)
}

/// Gives the x86 condition `cc` on a flags word.
#[must_use]
pub fn x86_cond(cc: Cc, flags: u16) -> bool {
    ghidorah_kernel::flags::x86_cond(cc.code(), flags)
}

/// Gives the flags that the hardware leaves undefined after `op`.
///
/// Tests mask these flags, and fusion never reads them. For shifts and rotates, the
/// hardware defines OF only for a count of 1, so the mask holds OF. For `shl` and `shr`,
/// the hardware also leaves CF undefined for a count of `w` or more. The mask does not
/// hold that CF.
#[must_use]
pub const fn undefined_mask(op: FlagOp) -> u16 {
    match op {
        FlagOp::X86Logic => AF,
        FlagOp::X86Shl | FlagOp::X86Shr | FlagOp::X86Sar => AF | OF,
        FlagOp::X86Rol | FlagOp::X86Ror => OF,
        FlagOp::X86UMul | FlagOp::X86SMul => SF | ZF | AF | PF,
        FlagOp::X86Bt => OF | SF | AF | PF,
        FlagOp::X86Add
        | FlagOp::X86Sub
        | FlagOp::X86Adc
        | FlagOp::X86Sbb
        | FlagOp::X86Inc
        | FlagOp::X86Dec
        | FlagOp::X86Neg
        | FlagOp::Copy => 0,
    }
}
