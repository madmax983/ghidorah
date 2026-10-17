//! K5 tier-1 tests: the flags, the conditions and the fusion table against a `u128` model
//! (AC-031, design Section 13.1).

use ghidorah_kernel::flags::{
    AF, CF, FuseOp, OF, PF, Pred, SF, ZF, eval_pred, flags_of, fused_pred, fused_rhs,
    x86_add_flags, x86_cond, x86_logic_flags, x86_sub_flags,
};
use ghidorah_testkit::pbt::{Gen, check};

use crate::support::json::Value;
use crate::support::results;

const OPS: [FuseOp; 3] = [FuseOp::Sub, FuseOp::Add, FuseOp::Logic];
const WIDTHS: [u32; 4] = [8, 16, 32, 64];

/// The mask of a width in the model.
fn model_mask(w: u32) -> u128 {
    (1u128 << w) - 1
}

/// The signed value of the low `w` bits.
fn model_signed(x: u128, w: u32) -> i128 {
    let sign = 1u128 << (w - 1);
    let x = x & model_mask(w);
    if x & sign == 0 {
        i128::try_from(x).expect("fits")
    } else {
        i128::try_from(x).expect("fits") - (1i128 << w)
    }
}

/// The `u128` model of the flags of `op`.
fn model_flags(op: FuseOp, a: u64, b: u64, w: u32) -> u16 {
    let m = model_mask(w);
    let (x, y) = (u128::from(a) & m, u128::from(b) & m);
    let (sx, sy) = (model_signed(x, w), model_signed(y, w));
    let lo = -(1i128 << (w - 1));
    let hi = (1i128 << (w - 1)) - 1;
    let (r, cf, of, af) = match op {
        FuseOp::Sub => {
            let s = sx - sy;
            (
                x.wrapping_sub(y) & m,
                x < y,
                s < lo || s > hi,
                (x & 0xf) < (y & 0xf),
            )
        }
        FuseOp::Add => {
            let s = sx + sy;
            (
                (x + y) & m,
                x + y > m,
                s < lo || s > hi,
                (x & 0xf) + (y & 0xf) > 0xf,
            )
        }
        FuseOp::Logic => (x & y, false, false, false),
    };
    let mut f = 0;
    for (set, bit) in [
        (cf, CF),
        ((r & 0xff).count_ones() % 2 == 0, PF),
        (af, AF),
        (r == 0, ZF),
        (r >> (w - 1) & 1 == 1, SF),
        (of, OF),
    ] {
        if set {
            f |= bit;
        }
    }
    f
}

/// The model of an x86 condition.
fn model_cond(cc: u8, f: u16) -> bool {
    let (cf, pf, zf, sf, of) = (
        f & CF != 0,
        f & PF != 0,
        f & ZF != 0,
        f & SF != 0,
        f & OF != 0,
    );
    let base = match (cc & 0xf) >> 1 {
        0 => of,
        1 => cf,
        2 => zf,
        3 => cf || zf,
        4 => sf,
        5 => pf,
        6 => sf != of,
        _ => zf || sf != of,
    };
    base != (cc & 1 == 1)
}

/// The model of a compare on the low `w` bits.
fn model_pred(p: Pred, a: u64, b: u64, w: u32) -> bool {
    let m = model_mask(w);
    let (x, y) = (u128::from(a) & m, u128::from(b) & m);
    let (sx, sy) = (model_signed(x, w), model_signed(y, w));
    match p {
        Pred::Eq => x == y,
        Pred::Ne => x != y,
        Pred::ULt => x < y,
        Pred::ULe => x <= y,
        Pred::UGt => x > y,
        Pred::UGe => x >= y,
        Pred::SLt => sx < sy,
        Pred::SLe => sx <= sy,
        Pred::SGt => sx > sy,
        Pred::SGe => sx >= sy,
        Pred::TestZ => x & y == 0,
        Pred::TestNZ => x & y != 0,
    }
}

/// The model of the right operand of a fused compare.
fn model_rhs(op: FuseOp, b: u64, w: u32) -> u64 {
    match op {
        FuseOp::Add => {
            u64::try_from((model_mask(w) + 1 - (u128::from(b) & model_mask(w))) & model_mask(w))
                .expect("fits")
        }
        FuseOp::Sub | FuseOp::Logic => b,
    }
}

/// Draws an operand with many edge values of each width.
fn operand(g: &mut Gen) -> u64 {
    const EDGES: [u64; 14] = [
        0,
        1,
        0x0f,
        0x10,
        0x7f,
        0x80,
        0xff,
        0x7fff,
        0x8000,
        0xffff,
        0x7fff_ffff,
        0x8000_0000,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
    ];
    match g.draw(4) {
        0 => *g.pick(&EDGES).expect("not empty"),
        1 => g.pick(&EDGES).expect("not empty").wrapping_sub(1),
        _ => g.u64(),
    }
}

/// Checks one input: the flags, every condition and every fused compare.
fn check_input(op: FuseOp, a: u64, b: u64, w: u32) -> Result<(), String> {
    let got = flags_of(op, a, b, w);
    let want = model_flags(op, a, b, w);
    if got != want {
        return Err(format!(
            "{op:?} w={w} a={a:#x} b={b:#x}: flags {got:#x}, model {want:#x}"
        ));
    }
    for cc in 0..16u8 {
        if x86_cond(cc, got) != model_cond(cc, got) {
            return Err(format!(
                "cc={cc} flags={got:#x}: x86_cond differs from the model"
            ));
        }
        let Some(p) = fused_pred(op, cc) else {
            continue;
        };
        let rhs = fused_rhs(op, b, w);
        if rhs != model_rhs(op, b, w) {
            return Err(format!("{op:?} w={w} b={b:#x}: fused_rhs {rhs:#x}"));
        }
        let fused = eval_pred(p, a, rhs, w);
        if fused != model_pred(p, a, rhs, w) {
            return Err(format!(
                "{p:?} w={w} a={a:#x} rhs={rhs:#x}: eval_pred differs"
            ));
        }
        if fused != model_cond(cc, want) {
            return Err(format!(
                "{op:?} cc={cc} w={w} a={a:#x} b={b:#x}: {p:?} gives {fused}"
            ));
        }
    }
    Ok(())
}

#[test]
fn k5_wide_random_against_u128() {
    check("k5_wide_random_against_u128", 20_000, |g| {
        let a = operand(g);
        let b = operand(g);
        for op in OPS {
            for w in WIDTHS {
                check_input(op, a, b, w)?;
            }
        }
        Ok(())
    });
}

#[test]
fn k5_exhaustive_8bit() {
    for op in OPS {
        for a in 0..=0xffu64 {
            for b in 0..=0xffu64 {
                if let Err(e) = check_input(op, a, b, 8) {
                    panic!("{e}");
                }
            }
        }
    }
}

#[test]
fn k5_flag_rows() {
    // (op, a, b, w, flags): rows from the Intel SDM rules.
    let rows: &[(FuseOp, u64, u64, u32, u16)] = &[
        (FuseOp::Sub, 0, 1, 8, CF | PF | AF | SF),
        (FuseOp::Sub, 5, 5, 32, ZF | PF),
        (FuseOp::Sub, 0x80, 1, 8, OF | AF),
        (FuseOp::Sub, 0x8000_0000_0000_0000, 1, 64, OF | AF | PF),
        (FuseOp::Add, 0xff, 1, 8, CF | ZF | PF | AF),
        (FuseOp::Add, 0x7f, 1, 8, OF | SF | AF),
        (FuseOp::Add, u64::MAX, u64::MAX, 64, CF | SF | AF),
        (FuseOp::Logic, 0xf0, 0x0f, 16, ZF | PF),
        (FuseOp::Logic, 0x8000, 0xffff, 16, SF | PF),
        // A width other than 8, 16 or 32 counts as 64.
        (FuseOp::Sub, 0, 1, 7, CF | PF | AF | SF),
    ];
    for &(op, a, b, w, want) in rows {
        assert_eq!(flags_of(op, a, b, w), want, "{op:?} {a:#x} {b:#x} w={w}");
    }
    assert_eq!(x86_sub_flags(3, 2, 8), flags_of(FuseOp::Sub, 3, 2, 8));
    assert_eq!(x86_add_flags(3, 2, 8), flags_of(FuseOp::Add, 3, 2, 8));
    assert_eq!(x86_logic_flags(3, 2, 8), flags_of(FuseOp::Logic, 3, 2, 8));
}

#[test]
fn k5_fused_table() {
    let sub = [
        (2, Pred::ULt),
        (3, Pred::UGe),
        (4, Pred::Eq),
        (5, Pred::Ne),
        (6, Pred::ULe),
        (7, Pred::UGt),
        (12, Pred::SLt),
        (13, Pred::SGe),
        (14, Pred::SLe),
        (15, Pred::SGt),
    ];
    let add = [(4, Pred::Eq), (5, Pred::Ne)];
    let logic = [
        (4, Pred::TestZ),
        (5, Pred::TestNZ),
        (6, Pred::TestZ),
        (7, Pred::TestNZ),
    ];
    for (op, table) in [
        (FuseOp::Sub, sub.as_slice()),
        (FuseOp::Add, add.as_slice()),
        (FuseOp::Logic, logic.as_slice()),
    ] {
        for cc in 0..=255u8 {
            let want = table.iter().find(|(k, _)| *k == cc & 0xf).map(|(_, p)| *p);
            assert_eq!(fused_pred(op, cc), want, "{op:?} cc={cc}");
        }
    }
}

#[test]
fn ac_031_k5_record() {
    let record = results().expect("verify/results.json exists and holds valid JSON");
    let k5 = record
        .pointer("/kernels/K5")
        .expect("the record has a K5 row");
    assert_eq!(
        k5.get("file").and_then(Value::as_str),
        Some("crates/kernel/src/flags.rs")
    );
    assert_eq!(k5.get("status").and_then(Value::as_str), Some("verified"));
    assert_eq!(k5.get("errors").and_then(Value::as_u64), Some(0));
    let verified = k5.get("verified").and_then(Value::as_u64).unwrap_or(0);
    let items = k5
        .get("spec_items")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    assert!(verified >= items, "K5 verifies each spec item");
    let negatives = record
        .pointer("/negatives")
        .and_then(Value::as_array)
        .expect("the record has negatives");
    let negative = negatives
        .iter()
        .find(|n| n.get("kernel").and_then(Value::as_str) == Some("K5"))
        .expect("K5 has a negative patch");
    assert_eq!(negative.get("ok"), Some(&Value::Bool(true)));
}
