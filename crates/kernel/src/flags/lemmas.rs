//! The proof lemmas of K5. Plain builds compile this module to nothing.
//!
//! Each `(op, width)` pair has one lemma with one `by (bit_vector)` query at a fixed width.
//! [`lemma_fuses`] joins them with the flag word facts of [`lemma_pack`].

#[cfg(verus_only)]
use vstd::prelude::*;

#[cfg(verus_only)]
verus! {

use super::{
    FuseOp, fuses, spec_mask, spec_pack, spec_parity, spec_sign, CF, OF, PF, SF, ZF,
};

/// The flag values of a packed word.
pub proof fn lemma_pack(cf: bool, pf: bool, af: bool, zf: bool, sf: bool, of: bool)
    ensures
        (spec_pack(cf, pf, af, zf, sf, of) & CF != 0) == cf,
        (spec_pack(cf, pf, af, zf, sf, of) & PF != 0) == pf,
        (spec_pack(cf, pf, af, zf, sf, of) & ZF != 0) == zf,
        (spec_pack(cf, pf, af, zf, sf, of) & SF != 0) == sf,
        (spec_pack(cf, pf, af, zf, sf, of) & OF != 0) == of,
{
    let f = spec_pack(cf, pf, af, zf, sf, of);
    assert(f == (if cf { 1u16 } else { 0u16 }) | (if pf { 4u16 } else { 0u16 }) | (if af {
        0x10u16
    } else {
        0u16
    }) | (if zf { 0x40u16 } else { 0u16 }) | (if sf { 0x80u16 } else { 0u16 }) | (if of {
        0x800u16
    } else {
        0u16
    }));
    assert((f & 1 != 0) == cf && (f & 4 != 0) == pf && (f & 0x40 != 0) == zf && (f & 0x80 != 0)
        == sf && (f & 0x800 != 0) == of) by (bit_vector)
        requires
            f == (if cf { 1u16 } else { 0u16 }) | (if pf { 4u16 } else { 0u16 }) | (if af {
                0x10u16
            } else {
                0u16
            }) | (if zf { 0x40u16 } else { 0u16 }) | (if sf { 0x80u16 } else { 0u16 }) | (if of {
                0x800u16
            } else {
                0u16
            }),
    ;
}

/// `wrapping_sub` is the bit-vector `sub`.
pub proof fn lemma_wrapping_sub(x: u64, y: u64)
    ensures
        (if x - y < 0 {
            (x - y + 0x1_0000_0000_0000_0000) as u64
        } else {
            (x - y) as u64
        }) == sub(x, y),
{
    assert((if x - y < 0 {
        (x - y + 0x1_0000_0000_0000_0000) as u64
    } else {
        (x - y) as u64
    }) == sub(x, y)) by (bit_vector);
}

/// `wrapping_add` is the bit-vector `add`.
pub proof fn lemma_wrapping_add(x: u64, y: u64)
    ensures
        (if x + y > 0xffff_ffff_ffff_ffff {
            (x + y - 0x1_0000_0000_0000_0000) as u64
        } else {
            (x + y) as u64
        }) == add(x, y),
{
    assert((if x + y > 0xffff_ffff_ffff_ffff {
        (x + y - 0x1_0000_0000_0000_0000) as u64
    } else {
        (x + y) as u64
    }) == add(x, y)) by (bit_vector);
}

/// `Sub` at 8 bits: ZF is `x == y`, and `SF != OF` is the signed `x < y`.
pub proof fn lemma_sub_8(a: u64, b: u64)
    ensures
        ({
        let (x, y) = (a & 0xff, b & 0xff);
        let r = sub(x, y) & 0xff;
        &&& (r == 0) == (x == y)
        &&& (x == y) == ((x ^ 0x80) == (y ^ 0x80))
        &&& ((r & 0x80 != 0) != ((x ^ y) & (x ^ r) & 0x80 != 0)) == ((x ^ 0x80) < (y ^ 0x80))
        }),
{
    assert({
        let (x, y) = (a & 0xff, b & 0xff);
        let r = sub(x, y) & 0xff;
        &&& (r == 0) == (x == y)
        &&& (x == y) == ((x ^ 0x80) == (y ^ 0x80))
        &&& ((r & 0x80 != 0) != ((x ^ y) & (x ^ r) & 0x80 != 0)) == ((x ^ 0x80) < (y ^ 0x80))
    }) by (bit_vector);
}

/// `Sub` at 16 bits: ZF is `x == y`, and `SF != OF` is the signed `x < y`.
pub proof fn lemma_sub_16(a: u64, b: u64)
    ensures
        ({
        let (x, y) = (a & 0xffff, b & 0xffff);
        let r = sub(x, y) & 0xffff;
        &&& (r == 0) == (x == y)
        &&& (x == y) == ((x ^ 0x8000) == (y ^ 0x8000))
        &&& ((r & 0x8000 != 0) != ((x ^ y) & (x ^ r) & 0x8000 != 0)) == ((x ^ 0x8000) < (y ^ 0x8000))
        }),
{
    assert({
        let (x, y) = (a & 0xffff, b & 0xffff);
        let r = sub(x, y) & 0xffff;
        &&& (r == 0) == (x == y)
        &&& (x == y) == ((x ^ 0x8000) == (y ^ 0x8000))
        &&& ((r & 0x8000 != 0) != ((x ^ y) & (x ^ r) & 0x8000 != 0)) == ((x ^ 0x8000) < (y ^ 0x8000))
    }) by (bit_vector);
}

/// `Sub` at 32 bits: ZF is `x == y`, and `SF != OF` is the signed `x < y`.
pub proof fn lemma_sub_32(a: u64, b: u64)
    ensures
        ({
        let (x, y) = (a & 0xffff_ffff, b & 0xffff_ffff);
        let r = sub(x, y) & 0xffff_ffff;
        &&& (r == 0) == (x == y)
        &&& (x == y) == ((x ^ 0x8000_0000) == (y ^ 0x8000_0000))
        &&& ((r & 0x8000_0000 != 0) != ((x ^ y) & (x ^ r) & 0x8000_0000 != 0)) == ((x ^ 0x8000_0000) < (y ^ 0x8000_0000))
        }),
{
    assert({
        let (x, y) = (a & 0xffff_ffff, b & 0xffff_ffff);
        let r = sub(x, y) & 0xffff_ffff;
        &&& (r == 0) == (x == y)
        &&& (x == y) == ((x ^ 0x8000_0000) == (y ^ 0x8000_0000))
        &&& ((r & 0x8000_0000 != 0) != ((x ^ y) & (x ^ r) & 0x8000_0000 != 0)) == ((x ^ 0x8000_0000) < (y ^ 0x8000_0000))
    }) by (bit_vector);
}

/// `Sub` at 64 bits: ZF is `x == y`, and `SF != OF` is the signed `x < y`.
pub proof fn lemma_sub_64(a: u64, b: u64)
    ensures
        ({
        let (x, y) = (a & 0xffff_ffff_ffff_ffff, b & 0xffff_ffff_ffff_ffff);
        let r = sub(x, y) & 0xffff_ffff_ffff_ffff;
        &&& (r == 0) == (x == y)
        &&& (x == y) == ((x ^ 0x8000_0000_0000_0000) == (y ^ 0x8000_0000_0000_0000))
        &&& ((r & 0x8000_0000_0000_0000 != 0) != ((x ^ y) & (x ^ r) & 0x8000_0000_0000_0000 != 0)) == ((x ^ 0x8000_0000_0000_0000) < (y ^ 0x8000_0000_0000_0000))
        }),
{
    assert({
        let (x, y) = (a & 0xffff_ffff_ffff_ffff, b & 0xffff_ffff_ffff_ffff);
        let r = sub(x, y) & 0xffff_ffff_ffff_ffff;
        &&& (r == 0) == (x == y)
        &&& (x == y) == ((x ^ 0x8000_0000_0000_0000) == (y ^ 0x8000_0000_0000_0000))
        &&& ((r & 0x8000_0000_0000_0000 != 0) != ((x ^ y) & (x ^ r) & 0x8000_0000_0000_0000 != 0)) == ((x ^ 0x8000_0000_0000_0000) < (y ^ 0x8000_0000_0000_0000))
    }) by (bit_vector);
}

/// `Add` at 8 bits: ZF is `x == -y`.
pub proof fn lemma_add_8(a: u64, b: u64)
    ensures
        ({
        let (x, y) = (a & 0xff, b & 0xff);
        ((add(x, y) & 0xff) == 0) == (x == ((sub(0, y) & 0xff) & 0xff))
        }),
{
    assert({
        let (x, y) = (a & 0xff, b & 0xff);
        ((add(x, y) & 0xff) == 0) == (x == ((sub(0, y) & 0xff) & 0xff))
    }) by (bit_vector);
}

/// `Add` at 16 bits: ZF is `x == -y`.
pub proof fn lemma_add_16(a: u64, b: u64)
    ensures
        ({
        let (x, y) = (a & 0xffff, b & 0xffff);
        ((add(x, y) & 0xffff) == 0) == (x == ((sub(0, y) & 0xffff) & 0xffff))
        }),
{
    assert({
        let (x, y) = (a & 0xffff, b & 0xffff);
        ((add(x, y) & 0xffff) == 0) == (x == ((sub(0, y) & 0xffff) & 0xffff))
    }) by (bit_vector);
}

/// `Add` at 32 bits: ZF is `x == -y`.
pub proof fn lemma_add_32(a: u64, b: u64)
    ensures
        ({
        let (x, y) = (a & 0xffff_ffff, b & 0xffff_ffff);
        ((add(x, y) & 0xffff_ffff) == 0) == (x == ((sub(0, y) & 0xffff_ffff) & 0xffff_ffff))
        }),
{
    assert({
        let (x, y) = (a & 0xffff_ffff, b & 0xffff_ffff);
        ((add(x, y) & 0xffff_ffff) == 0) == (x == ((sub(0, y) & 0xffff_ffff) & 0xffff_ffff))
    }) by (bit_vector);
}

/// `Add` at 64 bits: ZF is `x == -y`.
pub proof fn lemma_add_64(a: u64, b: u64)
    ensures
        ({
        let (x, y) = (a & 0xffff_ffff_ffff_ffff, b & 0xffff_ffff_ffff_ffff);
        ((add(x, y) & 0xffff_ffff_ffff_ffff) == 0) == (x == ((sub(0, y) & 0xffff_ffff_ffff_ffff) & 0xffff_ffff_ffff_ffff))
        }),
{
    assert({
        let (x, y) = (a & 0xffff_ffff_ffff_ffff, b & 0xffff_ffff_ffff_ffff);
        ((add(x, y) & 0xffff_ffff_ffff_ffff) == 0) == (x == ((sub(0, y) & 0xffff_ffff_ffff_ffff) & 0xffff_ffff_ffff_ffff))
    }) by (bit_vector);
}

/// `Logic` at 8 bits: the result is the `and` of the masked values.
pub proof fn lemma_logic_8(a: u64, b: u64)
    ensures
        (a & b & 0xff) == ((a & 0xff) & (b & 0xff)),
{
    assert((a & b & 0xff) == ((a & 0xff) & (b & 0xff))) by (bit_vector);
}

/// `Logic` at 16 bits: the result is the `and` of the masked values.
pub proof fn lemma_logic_16(a: u64, b: u64)
    ensures
        (a & b & 0xffff) == ((a & 0xffff) & (b & 0xffff)),
{
    assert((a & b & 0xffff) == ((a & 0xffff) & (b & 0xffff))) by (bit_vector);
}

/// `Logic` at 32 bits: the result is the `and` of the masked values.
pub proof fn lemma_logic_32(a: u64, b: u64)
    ensures
        (a & b & 0xffff_ffff) == ((a & 0xffff_ffff) & (b & 0xffff_ffff)),
{
    assert((a & b & 0xffff_ffff) == ((a & 0xffff_ffff) & (b & 0xffff_ffff))) by (bit_vector);
}

/// `Logic` at 64 bits: the result is the `and` of the masked values.
pub proof fn lemma_logic_64(a: u64, b: u64)
    ensures
        (a & b & 0xffff_ffff_ffff_ffff) == ((a & 0xffff_ffff_ffff_ffff) & (b & 0xffff_ffff_ffff_ffff)),
{
    assert((a & b & 0xffff_ffff_ffff_ffff) == ((a & 0xffff_ffff_ffff_ffff) & (b & 0xffff_ffff_ffff_ffff))) by (bit_vector);
}

/// Every fusable `(op, cc)` pair has the K5 property at every width.
pub proof fn lemma_fuses(op: FuseOp, cc: u8, a: u64, b: u64, w: u32)
    ensures
        fuses(op, cc, a, b, w),
{
    let m = spec_mask(w);
    let s = spec_sign(w);
    let x = a & m;
    let y = b & m;
    match op {
        FuseOp::Sub => {
            if w == 8 {
                lemma_sub_8(a, b);
            } else if w == 16 {
                lemma_sub_16(a, b);
            } else if w == 32 {
                lemma_sub_32(a, b);
            } else {
                lemma_sub_64(a, b);
            }
            let r = sub(x, y) & m;
            lemma_pack(
                x < y,
                spec_parity(r),
                (x ^ y ^ r) & 0x10 != 0,
                r == 0,
                r & s != 0,
                (x ^ y) & (x ^ r) & s != 0,
            );
        },
        FuseOp::Add => {
            if w == 8 {
                lemma_add_8(a, b);
            } else if w == 16 {
                lemma_add_16(a, b);
            } else if w == 32 {
                lemma_add_32(a, b);
            } else {
                lemma_add_64(a, b);
            }
            let r = add(x, y) & m;
            lemma_pack(
                r < x,
                spec_parity(r),
                (x ^ y ^ r) & 0x10 != 0,
                r == 0,
                r & s != 0,
                (x ^ r) & (y ^ r) & s != 0,
            );
        },
        FuseOp::Logic => {
            if w == 8 {
                lemma_logic_8(a, b);
            } else if w == 16 {
                lemma_logic_16(a, b);
            } else if w == 32 {
                lemma_logic_32(a, b);
            } else {
                lemma_logic_64(a, b);
            }
            let r = a & b & m;
            lemma_pack(false, spec_parity(r), false, r == 0, r & s != 0, false);
        },
    }
}

} // verus!
