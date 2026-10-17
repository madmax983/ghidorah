//! AC-068a and AC-068b: flag fusion against the semantic module and the interpreter.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers fail the test with a message"
)]

use ghidorah_ir::{
    Arg, Cc, Config, FlagOp, Loc, NoImage, Opc, Pred, StopReason, Val, eval, fuse, pred_opc,
    undefined_mask, x86_cond, x86_flags,
};
use ghidorah_testkit::pbt::Gen;
use ghidorah_testkit::rng::{Rng, Xoshiro256ss};

use crate::common::{program, run};

const A: Arg = Arg::V(Val(0));
const B: Arg = Arg::V(Val(1));

const PREDS: [Pred; 12] = [
    Pred::Eq,
    Pred::Ne,
    Pred::ULt,
    Pred::ULe,
    Pred::UGt,
    Pred::UGe,
    Pred::SLt,
    Pred::SLe,
    Pred::SGt,
    Pred::SGe,
    Pred::TestZ,
    Pred::TestNZ,
];

/// Gives the value of a fused argument: `A` is `a`, `B` is `b` and a constant is itself.
fn resolve(arg: Arg, a: u64, b: u64) -> u128 {
    match arg {
        A => u128::from(a),
        B => u128::from(b),
        Arg::K(k) => u128::from(k.get()),
        other => panic!("fuse gives the argument {other:?}"),
    }
}

/// The count of fused `(op, cc)` pairs when `b` is a value, then when `b` is a constant.
fn fused_pair_counts() -> (usize, usize) {
    let mut counts = (0, 0);
    for op in FlagOp::ALL {
        for cc in (0..16).filter_map(Cc::x86) {
            counts.0 += usize::from(fuse(*op, cc, A, B).is_some());
            counts.1 += usize::from(fuse(*op, cc, A, Arg::k(7)).is_some());
        }
    }
    counts
}

#[test]
fn ac_068a_fusion_exhaustive_8bit() {
    let mut checked = 0u64;
    for op in FlagOp::ALL {
        for cc in (0..16).filter_map(Cc::x86) {
            for const_b in [false, true] {
                let probe = if const_b { Arg::k(7) } else { B };
                if fuse(*op, cc, A, probe).is_none() {
                    continue;
                }
                for a in 0..=0xffu64 {
                    for b in 0..=0xffu64 {
                        let b_arg = if const_b { Arg::k(b) } else { B };
                        let (opc, x, y) = fuse(*op, cc, A, b_arg).expect("the pair fuses");
                        assert!(opc.is_compare(), "{op:?} {}: {opc}", cc.name());
                        let got = eval(opc, 8, 0, resolve(x, a, b), resolve(y, a, b), 0)
                            .expect("a compare evaluates");
                        for c in [0, 1] {
                            let flags = x86_flags(*op, 8, a, b, c);
                            let want = x86_cond(cc, flags);
                            assert_eq!(
                                got == 1,
                                want,
                                "{op:?} {} a={a:#x} b={b:#x} c={c}",
                                cc.name()
                            );
                            let flipped = flags ^ undefined_mask(*op);
                            assert_eq!(
                                x86_cond(cc, flipped),
                                want,
                                "{op:?} {} reads an undefined flag",
                                cc.name()
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    // Sub 10, Logic 4, Neg 10, Dec 6 and Inc 2 pairs fuse. Add fuses 2 more with a constant.
    assert_eq!(fused_pair_counts(), (32, 34));
    assert_eq!(checked, 66 * 65_536 * 2);
}

#[test]
fn fuse_rows() {
    let code = |n| Cc::x86(n).expect("a valid code");
    assert_eq!(fuse(FlagOp::X86Sub, code(4), A, B), Some((Opc::Eq, A, B)));
    assert_eq!(fuse(FlagOp::X86Sub, code(7), A, B), Some((Opc::ULt, B, A)));
    assert_eq!(fuse(FlagOp::X86Sub, code(13), A, B), Some((Opc::SLe, B, A)));
    assert_eq!(fuse(FlagOp::X86Sub, code(8), A, B), None);
    assert_eq!(fuse(FlagOp::X86Add, code(4), A, B), None);
    assert_eq!(
        fuse(FlagOp::X86Add, code(5), A, Arg::k(1)),
        Some((Opc::Ne, A, Arg::k(u64::MAX)))
    );
    assert_eq!(
        fuse(FlagOp::X86Logic, code(6), A, B),
        Some((Opc::TestZ, A, B))
    );
    assert_eq!(
        fuse(FlagOp::X86Neg, code(2), A, Arg::Nil),
        Some((Opc::ULt, Arg::k(0), A))
    );
    assert_eq!(
        fuse(FlagOp::X86Dec, code(5), A, Arg::Nil),
        Some((Opc::Ne, A, Arg::k(1)))
    );
    assert_eq!(fuse(FlagOp::X86Dec, code(2), A, Arg::Nil), None);
    assert_eq!(
        fuse(FlagOp::X86Inc, code(4), A, Arg::Nil),
        Some((Opc::Eq, A, Arg::k(u64::MAX)))
    );
    for op in [
        FlagOp::X86Adc,
        FlagOp::X86Shl,
        FlagOp::X86UMul,
        FlagOp::Copy,
    ] {
        for cc in (0..16).filter_map(Cc::x86) {
            assert_eq!(fuse(op, cc, A, B), None, "{op:?} {}", cc.name());
        }
    }
}

#[test]
fn pred_opc_is_total() {
    let want = [
        (Opc::Eq, false),
        (Opc::Ne, false),
        (Opc::ULt, false),
        (Opc::ULe, false),
        (Opc::ULt, true),
        (Opc::ULe, true),
        (Opc::SLt, false),
        (Opc::SLe, false),
        (Opc::SLt, true),
        (Opc::SLe, true),
        (Opc::TestZ, false),
        (Opc::TestNZ, false),
    ];
    for (p, (opc, swap)) in PREDS.into_iter().zip(want) {
        let args = if swap { (B, A) } else { (A, B) };
        assert_eq!(pred_opc(p, A, B), (opc, args.0, args.1), "{p:?}");
    }
}

/// Draws an operand with many edge values.
fn operand(rng: &mut Xoshiro256ss, g: &mut Gen) -> u64 {
    if rng.next_u64().is_multiple_of(2) {
        g.u64()
    } else {
        let shift = rng.next_u64() % 64;
        (1u64 << shift)
            .wrapping_add(rng.next_u64() % 3)
            .wrapping_sub(1)
    }
}

#[test]
fn ac_068b_pred_opc_all_widths() {
    let mut rng = Xoshiro256ss::seed_from_u64(0x068b);
    let mut draw = Gen::random(0x068b);
    for p in PREDS {
        for w in [8u8, 16, 32, 64] {
            let arena = program(|b| {
                b.begin(0x1000, 4)?;
                let lhs = b.get(Loc::RDI)?;
                let rhs = b.get(Loc::RSI)?;
                let (opc, left, right) = pred_opc(p, lhs.into(), rhs.into());
                let bit = b.binary(opc, w, left, right)?;
                let wide = b.extend(false, 64, 1, bit.into())?;
                b.put(Loc::RAX, wide.into())?;
                b.flow(Opc::Ret, Arg::Nil, Arg::Nil)
            });
            for _ in 0..10_000 {
                let (a, bv) = (operand(&mut rng, &mut draw), operand(&mut rng, &mut draw));
                let setup = [
                    (Loc::RDI, u128::from(a)),
                    (Loc::RSI, u128::from(bv)),
                    (Loc::RAX, 0xdead),
                ];
                let (stop, out) = run(
                    &arena,
                    &NoImage,
                    Config::default(),
                    &setup,
                    0x1000,
                    100,
                    &[Loc::RAX],
                );
                assert_eq!(stop.reason, StopReason::Returned);
                let want = ghidorah_kernel::eval_pred(p, a, bv, u32::from(w));
                assert_eq!(out, [u128::from(want)], "{p:?} w={w} a={a:#x} b={bv:#x}");
            }
        }
    }
}
