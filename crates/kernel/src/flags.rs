//! K5: the x86 flag fusion table (design Section 6.2, ADR-0009).
//!
//! A flag reader `Cond(cc, Flags(op, a, b))` can fuse into one compare.
//! [`fused_pred`] gives the compare, and [`eval_pred`] gives its value.
//! [`fused_rhs`] gives the right operand: `b` for `Sub` and `Logic`, and `-b` for `Add`.
//! Verus proves that the compare equals the condition on the flags at each width.
//! There is one lemma for each `(op, width)` pair, 12 in total, in `flags/lemmas.rs`.
//! The `ir` crate calls this table, so the proved table is the shipped table.
//!
//! A width of 8, 16 or 32 bits keeps its value. Each other width counts as 64 bits.
//!
//! | `op` | Fusable conditions |
//! |---|---|
//! | `Sub` | B, AE, E, NE, BE, A, L, GE, LE, G |
//! | `Add` | E, NE (the compare is `a == -b`) |
//! | `Logic` | E and BE (`TestZ`), NE and A (`TestNZ`) |

#[cfg(not(verus_only))]
use ghidorah_spec::{proof, verus_spec, verus_verify};
#[cfg(verus_only)]
use vstd::prelude::*;

mod lemmas;

/// The carry flag (bit 0).
#[verus_verify]
pub const CF: u16 = 0x0001;

/// The parity flag (bit 2). It is 1 when the low byte has an even count of 1 bits.
#[verus_verify]
pub const PF: u16 = 0x0004;

/// The adjust flag (bit 4): the carry or borrow at bit 3.
#[verus_verify]
pub const AF: u16 = 0x0010;

/// The zero flag (bit 6).
#[verus_verify]
pub const ZF: u16 = 0x0040;

/// The sign flag (bit 7).
#[verus_verify]
pub const SF: u16 = 0x0080;

/// The overflow flag (bit 11).
#[verus_verify]
pub const OF: u16 = 0x0800;

/// A flag operation that can fuse.
#[verus_verify]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FuseOp {
    /// `sub` and `cmp`: the flags of `a - b`.
    Sub,
    /// `add`: the flags of `a + b`.
    Add,
    /// `and` and `test`: the flags of `a & b`. CF and OF are 0.
    Logic,
}

/// A compare of two values at one width.
#[verus_verify]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pred {
    /// `a == b`.
    Eq,
    /// `a != b`.
    Ne,
    /// Unsigned `a < b`.
    ULt,
    /// Unsigned `a <= b`.
    ULe,
    /// Unsigned `a > b`.
    UGt,
    /// Unsigned `a >= b`.
    UGe,
    /// Signed `a < b`.
    SLt,
    /// Signed `a <= b`.
    SLe,
    /// Signed `a > b`.
    SGt,
    /// Signed `a >= b`.
    SGe,
    /// `a & b == 0`.
    TestZ,
    /// `a & b != 0`.
    TestNZ,
}

#[cfg(verus_only)]
verus! {

/// The value mask of a width.
pub open spec fn spec_mask(w: u32) -> u64 {
    if w == 8 {
        0xff
    } else if w == 16 {
        0xffff
    } else if w == 32 {
        0xffff_ffff
    } else {
        0xffff_ffff_ffff_ffff
    }
}

/// The sign bit of a width.
pub open spec fn spec_sign(w: u32) -> u64 {
    if w == 8 {
        0x80
    } else if w == 16 {
        0x8000
    } else if w == 32 {
        0x8000_0000
    } else {
        0x8000_0000_0000_0000
    }
}

/// The flag `bit` when `set` is true, else 0.
pub open spec fn spec_bit(set: bool, bit: u16) -> u16 {
    if set {
        bit
    } else {
        0
    }
}

/// The flags word of six flag values.
pub open spec fn spec_pack(cf: bool, pf: bool, af: bool, zf: bool, sf: bool, of: bool) -> u16 {
    spec_bit(cf, CF) | spec_bit(pf, PF) | spec_bit(af, AF) | spec_bit(zf, ZF) | spec_bit(sf, SF)
        | spec_bit(of, OF)
}

/// The parity flag of a result: the low byte has an even count of 1 bits.
pub open spec fn spec_parity(r: u64) -> bool {
    let v0 = r & 0xff;
    let v1 = v0 ^ (v0 >> 4u64);
    let v2 = v1 ^ (v1 >> 2u64);
    let v3 = v2 ^ (v2 >> 1u64);
    v3 & 1 == 0
}

/// The flags of `a - b`.
pub open spec fn spec_sub_flags(a: u64, b: u64, w: u32) -> u16 {
    let m = spec_mask(w);
    let s = spec_sign(w);
    let x = a & m;
    let y = b & m;
    let r = sub(x, y) & m;
    spec_pack(
        x < y,
        spec_parity(r),
        (x ^ y ^ r) & 0x10 != 0,
        r == 0,
        r & s != 0,
        (x ^ y) & (x ^ r) & s != 0,
    )
}

/// The flags of `a + b`.
pub open spec fn spec_add_flags(a: u64, b: u64, w: u32) -> u16 {
    let m = spec_mask(w);
    let s = spec_sign(w);
    let x = a & m;
    let y = b & m;
    let r = add(x, y) & m;
    spec_pack(
        r < x,
        spec_parity(r),
        (x ^ y ^ r) & 0x10 != 0,
        r == 0,
        r & s != 0,
        (x ^ r) & (y ^ r) & s != 0,
    )
}

/// The flags of `a & b`.
pub open spec fn spec_logic_flags(a: u64, b: u64, w: u32) -> u16 {
    let m = spec_mask(w);
    let r = a & b & m;
    spec_pack(false, spec_parity(r), false, r == 0, r & spec_sign(w) != 0, false)
}

/// The flags of `op`.
pub open spec fn spec_flags(op: FuseOp, a: u64, b: u64, w: u32) -> u16 {
    match op {
        FuseOp::Sub => spec_sub_flags(a, b, w),
        FuseOp::Add => spec_add_flags(a, b, w),
        FuseOp::Logic => spec_logic_flags(a, b, w),
    }
}

/// The x86 condition `cc` (the low nibble of the Jcc opcode) on a flags word.
pub open spec fn spec_cond(cc: u8, flags: u16) -> bool {
    let cf = flags & CF != 0;
    let pf = flags & PF != 0;
    let zf = flags & ZF != 0;
    let sf = flags & SF != 0;
    let of = flags & OF != 0;
    let k = cc & 0xf;
    if k == 0 {
        of
    } else if k == 1 {
        !of
    } else if k == 2 {
        cf
    } else if k == 3 {
        !cf
    } else if k == 4 {
        zf
    } else if k == 5 {
        !zf
    } else if k == 6 {
        cf || zf
    } else if k == 7 {
        !(cf || zf)
    } else if k == 8 {
        sf
    } else if k == 9 {
        !sf
    } else if k == 10 {
        pf
    } else if k == 11 {
        !pf
    } else if k == 12 {
        sf != of
    } else if k == 13 {
        sf == of
    } else if k == 14 {
        zf || sf != of
    } else {
        !zf && sf == of
    }
}

/// The fused compare of `op` and `cc`, or `None`.
pub open spec fn spec_fused_pred(op: FuseOp, cc: u8) -> Option<Pred> {
    let k = cc & 0xf;
    match op {
        FuseOp::Sub => if k == 2 {
            Some(Pred::ULt)
        } else if k == 3 {
            Some(Pred::UGe)
        } else if k == 4 {
            Some(Pred::Eq)
        } else if k == 5 {
            Some(Pred::Ne)
        } else if k == 6 {
            Some(Pred::ULe)
        } else if k == 7 {
            Some(Pred::UGt)
        } else if k == 12 {
            Some(Pred::SLt)
        } else if k == 13 {
            Some(Pred::SGe)
        } else if k == 14 {
            Some(Pred::SLe)
        } else if k == 15 {
            Some(Pred::SGt)
        } else {
            None
        },
        FuseOp::Add => if k == 4 {
            Some(Pred::Eq)
        } else if k == 5 {
            Some(Pred::Ne)
        } else {
            None
        },
        FuseOp::Logic => if k == 4 || k == 6 {
            Some(Pred::TestZ)
        } else if k == 5 || k == 7 {
            Some(Pred::TestNZ)
        } else {
            None
        },
    }
}

/// The right operand of the fused compare.
pub open spec fn spec_rhs(op: FuseOp, b: u64, w: u32) -> u64 {
    match op {
        FuseOp::Add => sub(0, b & spec_mask(w)) & spec_mask(w),
        _ => b,
    }
}

/// The value of a compare at width `w`.
pub open spec fn spec_eval_pred(p: Pred, a: u64, b: u64, w: u32) -> bool {
    let m = spec_mask(w);
    let s = spec_sign(w);
    let x = a & m;
    let y = b & m;
    match p {
        Pred::Eq => x == y,
        Pred::Ne => x != y,
        Pred::ULt => x < y,
        Pred::ULe => x <= y,
        Pred::UGt => x > y,
        Pred::UGe => x >= y,
        Pred::SLt => (x ^ s) < (y ^ s),
        Pred::SLe => (x ^ s) <= (y ^ s),
        Pred::SGt => (x ^ s) > (y ^ s),
        Pred::SGe => (x ^ s) >= (y ^ s),
        Pred::TestZ => x & y == 0,
        Pred::TestNZ => x & y != 0,
    }
}

/// The K5 property: the fused compare equals the condition on the flags.
pub open spec fn fuses(op: FuseOp, cc: u8, a: u64, b: u64, w: u32) -> bool {
    match spec_fused_pred(op, cc) {
        Some(p) => spec_cond(cc, spec_flags(op, a, b, w)) == spec_eval_pred(
            p,
            a,
            spec_rhs(op, b, w),
            w,
        ),
        None => true,
    }
}

} // verus!

/// Gives the value mask of a width.
#[verus_spec(r => ensures r == spec_mask(w))]
const fn mask(w: u32) -> u64 {
    match w {
        8 => 0xff,
        16 => 0xffff,
        32 => 0xffff_ffff,
        _ => u64::MAX,
    }
}

/// Gives the sign bit of a width.
#[verus_spec(r => ensures r == spec_sign(w))]
const fn sign(w: u32) -> u64 {
    match w {
        8 => 0x80,
        16 => 0x8000,
        32 => 0x8000_0000,
        _ => 0x8000_0000_0000_0000,
    }
}

/// Gives `value` when `set` is true, else 0.
#[verus_spec(r => ensures r == spec_bit(set, value))]
const fn bit(set: bool, value: u16) -> u16 {
    if set { value } else { 0 }
}

/// Gives the flags word of six flag values.
#[verus_spec(r => ensures r == spec_pack(cf, pf, af, zf, sf, of))]
#[expect(clippy::fn_params_excessive_bools, reason = "one value for each flag")]
const fn pack(cf: bool, pf: bool, af: bool, zf: bool, sf: bool, of: bool) -> u16 {
    bit(cf, CF) | bit(pf, PF) | bit(af, AF) | bit(zf, ZF) | bit(sf, SF) | bit(of, OF)
}

/// Tells if the low byte of `r` has an even count of 1 bits.
#[verus_spec(p => ensures p == spec_parity(r))]
const fn parity(r: u64) -> bool {
    let v0 = r & 0xff;
    let v1 = v0 ^ (v0 >> 4);
    let v2 = v1 ^ (v1 >> 2);
    let v3 = v2 ^ (v2 >> 1);
    v3 & 1 == 0
}

/// Gives the flags of `a - b` at width `w` (`sub`, `cmp`).
#[must_use]
#[verus_spec(r => ensures r == spec_sub_flags(a, b, w))]
pub fn x86_sub_flags(a: u64, b: u64, w: u32) -> u16 {
    let (low, top) = (mask(w), sign(w));
    let (lhs, rhs) = (a & low, b & low);
    let diff = lhs.wrapping_sub(rhs);
    proof! {
        lemmas::lemma_wrapping_sub(lhs, rhs);
    }
    let res = diff & low;
    pack(
        lhs < rhs,
        parity(res),
        (lhs ^ rhs ^ res) & 0x10 != 0,
        res == 0,
        res & top != 0,
        (lhs ^ rhs) & (lhs ^ res) & top != 0,
    )
}

/// Gives the flags of `a + b` at width `w` (`add`).
#[must_use]
#[verus_spec(r => ensures r == spec_add_flags(a, b, w))]
pub fn x86_add_flags(a: u64, b: u64, w: u32) -> u16 {
    let (low, top) = (mask(w), sign(w));
    let (lhs, rhs) = (a & low, b & low);
    let sum = lhs.wrapping_add(rhs);
    proof! {
        lemmas::lemma_wrapping_add(lhs, rhs);
    }
    let res = sum & low;
    pack(
        res < lhs,
        parity(res),
        (lhs ^ rhs ^ res) & 0x10 != 0,
        res == 0,
        res & top != 0,
        (lhs ^ res) & (rhs ^ res) & top != 0,
    )
}

/// Gives the flags of `a & b` at width `w` (`and`, `test`). AF is 0.
#[must_use]
#[verus_spec(r => ensures r == spec_logic_flags(a, b, w))]
pub fn x86_logic_flags(a: u64, b: u64, w: u32) -> u16 {
    let res = a & b & mask(w);
    pack(
        false,
        parity(res),
        false,
        res == 0,
        res & sign(w) != 0,
        false,
    )
}

/// Gives the flags of `op` on `a` and `b` at width `w`.
#[must_use]
#[verus_spec(r => ensures r == spec_flags(op, a, b, w))]
pub fn flags_of(op: FuseOp, a: u64, b: u64, w: u32) -> u16 {
    match op {
        FuseOp::Sub => x86_sub_flags(a, b, w),
        FuseOp::Add => x86_add_flags(a, b, w),
        FuseOp::Logic => x86_logic_flags(a, b, w),
    }
}

/// Gives the x86 condition `cc` on a flags word.
///
/// `cc` is the low nibble of the Jcc opcode: 0 is O, 2 is B, 4 is E and 12 is L.
#[must_use]
#[verus_spec(r => ensures r == spec_cond(cc, flags))]
pub const fn x86_cond(cc: u8, flags: u16) -> bool {
    let cf = flags & CF != 0;
    let pf = flags & PF != 0;
    let zf = flags & ZF != 0;
    let sf = flags & SF != 0;
    let of = flags & OF != 0;
    match cc & 0xf {
        0 => of,
        1 => !of,
        2 => cf,
        3 => !cf,
        4 => zf,
        5 => !zf,
        6 => cf || zf,
        7 => !(cf || zf),
        8 => sf,
        9 => !sf,
        10 => pf,
        11 => !pf,
        12 => sf != of,
        13 => sf == of,
        14 => zf || sf != of,
        _ => !zf && sf == of,
    }
}

/// Gives the compare that `Cond(cc, Flags(op, a, b))` fuses into, or `None`.
///
/// The compare takes `a` and the [`fused_rhs`] of `(op, b, w)`. Verus proves the K5 property
/// for every `a`, `b` and `w`: the compare equals [`x86_cond`] on [`flags_of`].
#[must_use]
#[verus_spec(r =>
    ensures
        r == spec_fused_pred(op, cc),
        forall|a: u64, b: u64, w: u32| #[trigger] fuses(op, cc, a, b, w),
)]
pub fn fused_pred(op: FuseOp, cc: u8) -> Option<Pred> {
    proof! {
        assert forall|a: u64, b: u64, w: u32| #[trigger] fuses(op, cc, a, b, w) by {
            lemmas::lemma_fuses(op, cc, a, b, w);
        }
    }
    let k = cc & 0xf;
    match op {
        FuseOp::Sub => match k {
            2 => Some(Pred::ULt),
            3 => Some(Pred::UGe),
            4 => Some(Pred::Eq),
            5 => Some(Pred::Ne),
            6 => Some(Pred::ULe),
            7 => Some(Pred::UGt),
            12 => Some(Pred::SLt),
            13 => Some(Pred::SGe),
            14 => Some(Pred::SLe),
            15 => Some(Pred::SGt),
            _ => None,
        },
        FuseOp::Add => match k {
            4 => Some(Pred::Eq),
            5 => Some(Pred::Ne),
            _ => None,
        },
        FuseOp::Logic => match k {
            4 | 6 => Some(Pred::TestZ),
            5 | 7 => Some(Pred::TestNZ),
            _ => None,
        },
    }
}

/// Gives the right operand of the fused compare: `-b` at width `w` for `Add`, else `b`.
#[must_use]
#[verus_spec(r => ensures r == spec_rhs(op, b, w))]
pub fn fused_rhs(op: FuseOp, b: u64, w: u32) -> u64 {
    match op {
        FuseOp::Add => {
            let low = mask(w);
            let rhs = b & low;
            let neg = 0u64.wrapping_sub(rhs);
            proof! {
                lemmas::lemma_wrapping_sub(0, rhs);
            }
            neg & low
        }
        FuseOp::Sub | FuseOp::Logic => b,
    }
}

/// Gives the value of the compare `p` on `a` and `b` at width `w`.
///
/// The compare reads the low `w` bits of each value. A signed compare reads bit `w - 1`
/// as the sign.
#[must_use]
#[verus_spec(r => ensures r == spec_eval_pred(p, a, b, w))]
pub fn eval_pred(p: Pred, a: u64, b: u64, w: u32) -> bool {
    let (low, top) = (mask(w), sign(w));
    let (lhs, rhs) = (a & low, b & low);
    match p {
        Pred::Eq => lhs == rhs,
        Pred::Ne => lhs != rhs,
        Pred::ULt => lhs < rhs,
        Pred::ULe => lhs <= rhs,
        Pred::UGt => lhs > rhs,
        Pred::UGe => lhs >= rhs,
        Pred::SLt => (lhs ^ top) < (rhs ^ top),
        Pred::SLe => (lhs ^ top) <= (rhs ^ top),
        Pred::SGt => (lhs ^ top) > (rhs ^ top),
        Pred::SGe => (lhs ^ top) >= (rhs ^ top),
        Pred::TestZ => lhs & rhs == 0,
        Pred::TestNZ => lhs & rhs != 0,
    }
}
