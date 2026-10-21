//! The flag semantic module: one row table for each flag operation (design Section 6.2).

use ghidorah_ir::sem::{AF, CF, OF, PF, SF, STATUS, ZF};
use ghidorah_ir::{Cc, FlagOp, undefined_mask, x86_cond, x86_flags};
use ghidorah_testkit::pbt::check;

/// `(op, w, a, b, c, flags)`: rows from the Intel SDM rules. The test masks undefined flags.
const ROWS: &[(FlagOp, u8, u64, u64, u64, u16)] = &[
    (FlagOp::X86Add, 8, 0xff, 1, 0, CF | ZF | PF | AF),
    (FlagOp::X86Sub, 8, 0, 1, 0, CF | PF | AF | SF),
    (FlagOp::X86Adc, 8, 0xff, 0, 1, CF | ZF | PF | AF),
    (FlagOp::X86Adc, 8, 0x7f, 0, 1, OF | SF | AF),
    (FlagOp::X86Adc, 8, 1, 1, 0, 0),
    (FlagOp::X86Adc, 64, u64::MAX, u64::MAX, 1, CF | SF | PF | AF),
    (FlagOp::X86Sbb, 8, 0, 0, 1, CF | PF | AF | SF),
    (FlagOp::X86Sbb, 8, 0x80, 0, 1, OF | AF),
    (FlagOp::X86Sbb, 8, 5, 3, 1, 0),
    (FlagOp::X86Sbb, 32, 0, 0xffff_ffff, 1, CF | ZF | PF | AF),
    (FlagOp::X86Logic, 8, 0x0f, 0xf0, 0, ZF | PF),
    (FlagOp::X86Inc, 8, 0xff, 0, CF as u64, CF | ZF | PF | AF),
    (FlagOp::X86Inc, 8, 0x7f, 0, 0, OF | SF | AF),
    (FlagOp::X86Inc, 8, 0x7f, 0, CF as u64, CF | OF | SF | AF),
    (FlagOp::X86Dec, 8, 0, 0, 0, PF | AF | SF),
    (FlagOp::X86Dec, 8, 0x80, 0, CF as u64, CF | AF | OF),
    (FlagOp::X86Dec, 8, 1, 0, 0, ZF | PF),
    (FlagOp::X86Neg, 8, 0, 0, 0, ZF | PF),
    (FlagOp::X86Neg, 8, 1, 0, 0, CF | PF | AF | SF),
    (FlagOp::X86Neg, 8, 0x80, 0, 0, CF | SF | OF),
    (FlagOp::X86Shl, 8, 0x81, 1, 0, CF | OF),
    (FlagOp::X86Shl, 8, 0x40, 1, 0, SF | OF),
    (
        FlagOp::X86Shl,
        8,
        0x01,
        0,
        (ZF | PF | CF) as u64,
        ZF | PF | CF,
    ),
    (FlagOp::X86Shl, 8, 0x01, 8, 0, CF | ZF | PF),
    (FlagOp::X86Shl, 64, 1 << 63, 1, 0, CF | ZF | PF | OF),
    // The thunk masks a 32-bit count to 5 bits: 33 shifts by 1.
    (FlagOp::X86Shl, 32, 3, 33, 0, PF),
    (FlagOp::X86Shr, 8, 0x81, 1, 0, CF | OF),
    (FlagOp::X86Shr, 8, 0x02, 2, 0, CF | ZF | PF),
    (FlagOp::X86Shr, 16, 0x8000, 0, SF as u64, SF),
    (FlagOp::X86Sar, 8, 0x81, 1, 0, CF | PF | SF),
    (FlagOp::X86Sar, 8, 0x80, 9, 0, CF | PF | SF),
    (FlagOp::X86Sar, 64, 2, 1, 0, 0),
    (
        FlagOp::X86Rol,
        8,
        0x81,
        1,
        (ZF | SF) as u64,
        ZF | SF | CF | OF,
    ),
    (FlagOp::X86Rol, 8, 0x81, 0, (ZF | SF) as u64, ZF | SF),
    (FlagOp::X86Rol, 8, 0x80, 8, 0, 0),
    (FlagOp::X86Ror, 8, 0x01, 1, 0, CF | OF),
    (FlagOp::X86Ror, 8, 0x02, 1, PF as u64, PF),
    (FlagOp::X86UMul, 8, 0x10, 0x10, 0, CF | OF),
    (FlagOp::X86UMul, 8, 2, 3, 0, 0),
    (FlagOp::X86UMul, 64, u64::MAX, 2, 0, CF | OF),
    (FlagOp::X86SMul, 8, 0x40, 2, 0, CF | OF),
    (FlagOp::X86SMul, 8, 0xff, 0x80, 0, CF | OF),
    (FlagOp::X86SMul, 8, 0xff, 0xff, 0, 0),
    (
        FlagOp::X86SMul,
        64,
        u64::MAX,
        0x8000_0000_0000_0000,
        0,
        CF | OF,
    ),
    (FlagOp::X86Bt, 16, 0x8000, 15, ZF as u64, CF | ZF),
    (FlagOp::X86Bt, 16, 0x8000, 31, 0, CF),
    (FlagOp::X86Bt, 64, 0, 3, 0, 0),
    (FlagOp::Copy, 16, 0xffff, 0, 0, STATUS),
    (FlagOp::Copy, 16, 0x0001, 0, 0, CF),
];

#[test]
fn flag_rows_of_every_operation() {
    for &(op, w, a, b, c, want) in ROWS {
        let keep = !undefined_mask(op);
        assert_eq!(
            x86_flags(op, w, a, b, c) & keep,
            want & keep,
            "{op:?} w={w} a={a:#x} b={b:#x} c={c:#x}"
        );
    }
    for op in FlagOp::ALL {
        assert!(
            ROWS.iter().any(|r| r.0 == *op),
            "{op:?} has a row in the table"
        );
    }
}

#[test]
fn flags_stay_in_the_status_bits() {
    for op in FlagOp::ALL {
        for (a, b) in [(0, 0), (u64::MAX, u64::MAX), (0x80, 1), (1, 63)] {
            for w in [8, 16, 32, 64] {
                let f = x86_flags(*op, w, a, b, u64::MAX);
                assert_eq!(f & !STATUS, 0, "{op:?} w={w}: {f:#x}");
            }
        }
    }
}

#[test]
fn undefined_masks() {
    let rows = [
        (FlagOp::X86Add, 0),
        (FlagOp::X86Sub, 0),
        (FlagOp::X86Adc, 0),
        (FlagOp::X86Sbb, 0),
        (FlagOp::X86Logic, AF),
        (FlagOp::X86Inc, 0),
        (FlagOp::X86Dec, 0),
        (FlagOp::X86Neg, 0),
        (FlagOp::X86Shl, AF | OF),
        (FlagOp::X86Shr, AF | OF),
        (FlagOp::X86Sar, AF | OF),
        (FlagOp::X86Rol, OF),
        (FlagOp::X86Ror, OF),
        (FlagOp::X86UMul, SF | ZF | AF | PF),
        (FlagOp::X86SMul, SF | ZF | AF | PF),
        (FlagOp::X86Bt, OF | SF | AF | PF),
        (FlagOp::Copy, 0),
    ];
    assert_eq!(rows.len(), FlagOp::ALL.len());
    for (op, mask) in rows {
        assert_eq!(undefined_mask(op), mask, "{op:?}");
    }
}

#[test]
fn conditions_read_the_flag_bits() {
    let cases = [
        (0, OF, true),
        (1, OF, false),
        (2, CF, true),
        (3, 0, true),
        (4, ZF, true),
        (5, ZF, false),
        (6, CF, true),
        (7, ZF, false),
        (8, SF, true),
        (9, SF, false),
        (10, PF, true),
        (11, PF, false),
        (12, SF, true),
        (12, SF | OF, false),
        (13, SF | OF, true),
        (14, ZF, true),
        (15, 0, true),
        (15, SF, false),
    ];
    for (code, flags, want) in cases {
        let cc = Cc::x86(code).expect("a valid code");
        assert_eq!(x86_cond(cc, flags), want, "{} on {flags:#x}", cc.name());
    }
    assert_eq!(Cc::x86(16), None);
    let names: Vec<&str> = (0..16).filter_map(Cc::x86).map(Cc::name).collect();
    assert_eq!(names.join(" "), "o no b ae e ne be a s ns p np l ge le g");
}

/// The ZF, SF and PF flags of a model result.
fn model_result(res: u128, w: u32) -> u16 {
    let mut flags = 0;
    if res == 0 {
        flags |= ZF;
    }
    if (res >> (w - 1)) & 1 == 1 {
        flags |= SF;
    }
    if (res & 0xff).count_ones().is_multiple_of(2) {
        flags |= PF;
    }
    flags
}

/// The signed value of the low `w` bits.
fn model_signed(x: u128, w: u32) -> i128 {
    let shift = 128 - w;
    (x << shift).cast_signed() >> shift
}

/// Gives `value` when `set` is true, else 0.
const fn bit(set: bool, value: u16) -> u16 {
    if set { value } else { 0 }
}

/// The model of the shifts at a count from 1 to `w - 1`.
fn model_shift(op: FlagOp, w: u32, lhs: u128, cnt: u32) -> u16 {
    let low = (1u128 << w) - 1;
    let (res, cf, of) = match op {
        FlagOp::X86Shl => {
            let wide = lhs << cnt;
            let cf = (wide >> w) & 1 == 1;
            (wide & low, cf, ((wide >> (w - 1)) & 1 == 1) != cf)
        }
        FlagOp::X86Shr => (
            lhs >> cnt,
            (lhs >> (cnt - 1)) & 1 == 1,
            (lhs >> (w - 1)) & 1 == 1,
        ),
        _ => (
            (model_signed(lhs, w) >> cnt).cast_unsigned() & low,
            (lhs >> (cnt - 1)) & 1 == 1,
            false,
        ),
    };
    bit(cf, CF) | bit(of, OF) | model_result(res, w)
}

/// The model of the rotates. A masked count of 0 keeps the old flags.
fn model_rotate(op: FlagOp, w: u32, lhs: u128, cnt: u128, old: u16) -> u16 {
    if cnt == 0 {
        return old;
    }
    let low = (1u128 << w) - 1;
    let turn = u32::try_from(cnt % u128::from(w)).unwrap_or(0);
    let res = if turn == 0 {
        lhs
    } else if op == FlagOp::X86Rol {
        ((lhs << turn) | (lhs >> (w - turn))) & low
    } else {
        ((lhs >> turn) | (lhs << (w - turn))) & low
    };
    let top = (res >> (w - 1)) & 1 == 1;
    let (cf, of) = if op == FlagOp::X86Rol {
        (res & 1 == 1, top != (res & 1 == 1))
    } else {
        (top, top != ((res >> (w - 2)) & 1 == 1))
    };
    (old & !(CF | OF)) | bit(cf, CF) | bit(of, OF)
}

/// The `u128` model of the flags of the operations outside K5. `old` is the old flags word.
fn model_flags(op: FlagOp, w: u32, a: u64, b: u64, old: u16) -> u16 {
    let low = (1u128 << w) - 1;
    let (lhs, rhs) = (u128::from(a) & low, u128::from(b) & low);
    let (slhs, srhs) = (model_signed(lhs, w), model_signed(rhs, w));
    let (min, max) = (-(1i128 << (w - 1)), (1i128 << (w - 1)) - 1);
    let out = |exact: i128| exact < min || exact > max;
    let cin = u128::from(old & CF);
    let cnt = u128::from(b) & if w == 64 { 63 } else { 31 };
    match op {
        FlagOp::X86Adc => {
            let full = lhs + rhs + cin;
            bit(full > low, CF)
                | bit(out(slhs + srhs + cin.cast_signed()), OF)
                | bit((lhs & 0xf) + (rhs & 0xf) + cin > 0xf, AF)
                | model_result(full & low, w)
        }
        FlagOp::X86Sbb => {
            let full = lhs.cast_signed() - rhs.cast_signed() - cin.cast_signed();
            bit(full < 0, CF)
                | bit(out(slhs - srhs - cin.cast_signed()), OF)
                | bit((lhs & 0xf) < (rhs & 0xf) + cin, AF)
                | model_result(full.cast_unsigned() & low, w)
        }
        FlagOp::X86Inc => {
            (old & CF)
                | bit(out(slhs + 1), OF)
                | bit(lhs & 0xf == 0xf, AF)
                | model_result((lhs + 1) & low, w)
        }
        FlagOp::X86Dec => {
            (old & CF)
                | bit(out(slhs - 1), OF)
                | bit(lhs.trailing_zeros() >= 4, AF)
                | model_result(lhs.wrapping_sub(1) & low, w)
        }
        FlagOp::X86Neg => {
            bit(lhs != 0, CF)
                | bit(out(-slhs), OF)
                | bit(lhs & 0xf != 0, AF)
                | model_result(lhs.wrapping_neg() & low, w)
        }
        FlagOp::X86UMul => bit((lhs * rhs) >> w != 0, CF | OF),
        FlagOp::X86SMul => bit(out(slhs * srhs), CF | OF),
        FlagOp::X86Bt => bit((lhs >> (u128::from(b) % u128::from(w))) & 1 == 1, CF) | (old & ZF),
        FlagOp::X86Shl | FlagOp::X86Shr | FlagOp::X86Sar => {
            model_shift(op, w, lhs, u32::try_from(cnt).unwrap_or(0))
        }
        _ => model_rotate(op, w, lhs, cnt, old),
    }
}

#[test]
fn flag_operations_against_u128_model() {
    let ops = [
        FlagOp::X86Adc,
        FlagOp::X86Sbb,
        FlagOp::X86Inc,
        FlagOp::X86Dec,
        FlagOp::X86Neg,
        FlagOp::X86UMul,
        FlagOp::X86SMul,
        FlagOp::X86Bt,
        FlagOp::X86Shl,
        FlagOp::X86Shr,
        FlagOp::X86Sar,
        FlagOp::X86Rol,
        FlagOp::X86Ror,
    ];
    check("flag_operations_against_u128_model", 4_000, |g| {
        let a = g.u64();
        let old = u16::try_from(g.draw(0x1000)).unwrap_or(0) & STATUS;
        for w in [8u32, 16, 32, 64] {
            for op in ops {
                let shift = matches!(op, FlagOp::X86Shl | FlagOp::X86Shr | FlagOp::X86Sar);
                let rotate = matches!(op, FlagOp::X86Rol | FlagOp::X86Ror);
                // A shift count from 1 to w - 1: the other counts leave CF undefined.
                let b = if shift {
                    g.range(1, u64::from(w) - 1)
                } else {
                    g.u64()
                };
                let cnt = b & if w == 64 { 63 } else { 31 };
                let mut keep = !undefined_mask(op);
                if (shift || rotate) && cnt == 1 {
                    keep |= OF;
                }
                let width = u8::try_from(w).unwrap_or(64);
                let got = x86_flags(op, width, a, b, u64::from(old));
                let want = model_flags(op, w, a, b, old);
                if got & keep != want & keep {
                    return Err(format!(
                        "{op:?} w={w} a={a:#x} b={b:#x} old={old:#x}: {got:#x}, model {want:#x}"
                    ));
                }
            }
        }
        Ok(())
    });
}
