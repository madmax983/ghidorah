//! The data op table of the interpreter: one row or more for each data opcode.

use ghidorah_ir::sem::{AF, CF, PF, SF, STATUS, ZF};
use ghidorah_ir::{EvalError, FlagOp, Opc, eval};

const M64: u128 = u64::MAX as u128;
const TOP: u128 = 1 << 127;
const BASE: u128 = 0x1111_2222_3333_4444;

/// `(opc, w, sub, x, y, z, result)`.
type Row = (Opc, u8, u8, u128, u128, u128, Result<u128, EvalError>);

const ROWS: &[Row] = &[
    (Opc::Copy, 8, 0, 0x1ff, 0, 0, Ok(0xff)),
    (Opc::Add, 8, 0, 0xff, 1, 0, Ok(0)),
    (Opc::Add, 128, 0, u128::MAX, 2, 0, Ok(1)),
    (Opc::Sub, 16, 0, 0, 1, 0, Ok(0xffff)),
    (Opc::Mul, 32, 0, 0x10000, 0x10000, 0, Ok(0)),
    (Opc::Mul, 64, 0, 3, 5, 0, Ok(15)),
    (Opc::Mul, 128, 0, TOP, 2, 0, Ok(0)),
    (Opc::UMulHi, 32, 0, 0x10000, 0x10000, 0, Ok(1)),
    (Opc::UMulHi, 64, 0, M64, M64, 0, Ok(0xffff_ffff_ffff_fffe)),
    (Opc::UMulHi, 128, 0, u128::MAX, 2, 0, Ok(1)),
    (
        Opc::UMulHi,
        128,
        0,
        u128::MAX,
        u128::MAX,
        0,
        Ok(u128::MAX - 1),
    ),
    (Opc::SMulHi, 8, 0, 0xff, 0xff, 0, Ok(0)),
    (Opc::SMulHi, 8, 0, 0x80, 2, 0, Ok(0xff)),
    (Opc::SMulHi, 64, 0, M64, 2, 0, Ok(M64)),
    (Opc::SMulHi, 128, 0, u128::MAX, u128::MAX, 0, Ok(0)),
    (Opc::SMulHi, 128, 0, TOP, 2, 0, Ok(u128::MAX)),
    (Opc::UDiv, 8, 0, 7, 2, 0, Ok(3)),
    (Opc::URem, 8, 0, 7, 2, 0, Ok(1)),
    (Opc::SDiv, 8, 0, 0xf9, 2, 0, Ok(0xfd)),
    (Opc::SRem, 8, 0, 0xf9, 2, 0, Ok(0xff)),
    (Opc::SDiv, 8, 0, 0x80, 0xff, 0, Ok(0x80)),
    (Opc::SRem, 8, 0, 0x80, 0xff, 0, Ok(0)),
    (Opc::SDiv, 128, 0, TOP, u128::MAX, 0, Ok(TOP)),
    (Opc::UDiv, 64, 0, 1, 0, 0, Err(EvalError::DivZero)),
    (
        Opc::SRem,
        32,
        0,
        1,
        0x1_0000_0000,
        0,
        Err(EvalError::DivZero),
    ),
    (Opc::Neg, 8, 0, 1, 0, 0, Ok(0xff)),
    (Opc::Not, 16, 0, 0, 0, 0, Ok(0xffff)),
    (Opc::And, 8, 0, 0xf0, 0x3c, 0, Ok(0x30)),
    (Opc::Or, 8, 0, 0xf0, 0x3c, 0, Ok(0xfc)),
    (Opc::Xor, 8, 0, 0xf0, 0x3c, 0, Ok(0xcc)),
    (Opc::Shl, 8, 0, 0x81, 1, 0, Ok(0x02)),
    (Opc::Shl, 8, 0, 1, 8, 0, Ok(0)),
    (Opc::Shl, 128, 0, 1, 127, 0, Ok(TOP)),
    (Opc::LShr, 8, 0, 0x80, 7, 0, Ok(1)),
    (Opc::LShr, 64, 0, 1, 64, 0, Ok(0)),
    (Opc::AShr, 8, 0, 0x80, 7, 0, Ok(0xff)),
    (Opc::AShr, 8, 0, 0x80, 200, 0, Ok(0xff)),
    (Opc::AShr, 8, 0, 0x40, 9, 0, Ok(0)),
    (Opc::AShr, 128, 0, TOP, 127, 0, Ok(u128::MAX)),
    (Opc::Rol, 8, 0, 0x81, 1, 0, Ok(0x03)),
    (Opc::Rol, 8, 0, 0x81, 9, 0, Ok(0x03)),
    (Opc::Ror, 8, 0, 0x01, 1, 0, Ok(0x80)),
    (Opc::Ror, 16, 0, 0x1234, 16, 0, Ok(0x1234)),
    (Opc::Ror, 128, 0, 1, 1, 0, Ok(TOP)),
    (Opc::ZExt, 64, 8, 0x1ff, 0, 0, Ok(0xff)),
    (Opc::SExt, 64, 8, 0x80, 0, 0, Ok(0xffff_ffff_ffff_ff80)),
    (Opc::SExt, 128, 64, 1 << 63, 0, 0, Ok(u128::MAX << 63)),
    (Opc::SExt, 16, 32, 1, 0, 0, Err(EvalError::BadWidth)),
    (Opc::ZExt, 8, 0, 1, 0, 0, Err(EvalError::BadWidth)),
    (Opc::Trunc, 8, 0, 0x1234, 0, 0, Ok(0x34)),
    (Opc::Extract, 8, 0, 0x1234, 8, 0, Ok(0x12)),
    (Opc::Extract, 64, 0, (0xaa << 64) | 1, 64, 0, Ok(0xaa)),
    (Opc::Extract, 8, 0, 0x1234, 200, 0, Ok(0)),
    (
        Opc::Insert,
        64,
        8,
        BASE,
        0x1ff,
        8,
        Ok(0x1111_2222_3333_ff44),
    ),
    (Opc::Insert, 128, 64, 5, 7, 64, Ok((7 << 64) | 5)),
    (Opc::Insert, 64, 16, BASE, 1, 56, Err(EvalError::BadWidth)),
    (Opc::Insert, 64, 0, BASE, 1, 0, Err(EvalError::BadWidth)),
    (Opc::Popcnt, 16, 0, 0xff_ff0f, 0, 0, Ok(12)),
    (Opc::Clz, 32, 0, 1, 0, 0, Ok(31)),
    (Opc::Clz, 32, 0, 0, 0, 0, Ok(32)),
    (Opc::Clz, 128, 0, 1, 0, 0, Ok(127)),
    (Opc::Ctz, 8, 0, 0, 0, 0, Ok(8)),
    (Opc::Ctz, 64, 0, 0x100, 0, 0, Ok(8)),
    (Opc::Bswap, 32, 0, 0x1122_3344, 0, 0, Ok(0x4433_2211)),
    (Opc::Bswap, 16, 0, 0x1122, 0, 0, Ok(0x2211)),
    (Opc::Bswap, 128, 0, 1, 0, 0, Ok(1 << 120)),
    (Opc::Bswap, 12, 0, 1, 0, 0, Err(EvalError::BadWidth)),
    (Opc::Eq, 8, 0, 0x1ff, 0xff, 0, Ok(1)),
    (Opc::Ne, 8, 0, 0x1ff, 0xff, 0, Ok(0)),
    (Opc::ULt, 8, 0, 1, 0xff, 0, Ok(1)),
    (Opc::ULe, 64, 0, 5, 4, 0, Ok(0)),
    (Opc::SLt, 8, 0, 1, 0xff, 0, Ok(0)),
    (Opc::SLe, 8, 0, 0xff, 0xff, 0, Ok(1)),
    (Opc::SLt, 128, 0, TOP, 0, 0, Ok(1)),
    (Opc::TestZ, 8, 0, 0xf0, 0x0f, 0, Ok(1)),
    (Opc::TestNZ, 8, 0, 0xf0, 0x1f, 0, Ok(1)),
    (Opc::Ite, 32, 0, 1, 5, 6, Ok(5)),
    (Opc::Ite, 32, 0, 0, 5, 6, Ok(6)),
    (Opc::Ite, 8, 0, 2, 0x1ff, 0, Ok(0xff)),
    (
        Opc::Flags,
        8,
        FlagOp::X86Sub as u8,
        0,
        1,
        0,
        Ok((CF | PF | AF | SF) as u128),
    ),
    (
        Opc::Flags,
        12,
        FlagOp::X86Sub as u8,
        0,
        1,
        0,
        Err(EvalError::BadWidth),
    ),
    (Opc::Flags, 8, 99, 0, 1, 0, Err(EvalError::BadWidth)),
    (Opc::Cond, 1, 4, ZF as u128, 0, 0, Ok(1)),
    (Opc::Cond, 1, 5, ZF as u128, 0, 0, Ok(0)),
    (Opc::Cond, 1, 16, 0, 0, 0, Err(EvalError::BadWidth)),
    (Opc::FlagsSel, 16, 0, 1, 0x41, 0x80, Ok(0x41)),
    (Opc::FlagsSel, 16, 0, 0, 0x41, 0x80, Ok(0x80)),
    (Opc::FlagsGet, 64, 0, 0x8d5, 0, 0, Ok(0x8d5)),
    (Opc::FlagsSet, 16, 0, 0xffff, 0, 0, Ok(STATUS as u128)),
    (Opc::Get, 64, 0, 0, 0, 0, Err(EvalError::NotData)),
    (Opc::Load, 64, 0, 0, 0, 0, Err(EvalError::NotData)),
    (Opc::Phi, 64, 0, 0, 0, 0, Err(EvalError::NotData)),
    (Opc::Jump, 64, 0, 0, 0, 0, Err(EvalError::NotData)),
    (Opc::Add, 0, 0, 1, 1, 0, Err(EvalError::BadWidth)),
    (Opc::Add, 129, 0, 1, 1, 0, Err(EvalError::BadWidth)),
];

#[test]
fn eval_rows_of_every_data_op() {
    for &(opc, w, sub, x, y, z, want) in ROWS {
        assert_eq!(
            eval(opc, w, sub, x, y, z),
            want,
            "{opc}.{w} #{sub} {x:#x} {y:#x} {z:#x}"
        );
    }
    let data = [
        Opc::Copy,
        Opc::Add,
        Opc::Sub,
        Opc::Mul,
        Opc::UMulHi,
        Opc::SMulHi,
        Opc::UDiv,
        Opc::SDiv,
        Opc::URem,
        Opc::SRem,
        Opc::Neg,
        Opc::Not,
        Opc::And,
        Opc::Or,
        Opc::Xor,
        Opc::Shl,
        Opc::LShr,
        Opc::AShr,
        Opc::Rol,
        Opc::Ror,
        Opc::ZExt,
        Opc::SExt,
        Opc::Trunc,
        Opc::Extract,
        Opc::Insert,
        Opc::Popcnt,
        Opc::Clz,
        Opc::Ctz,
        Opc::Bswap,
        Opc::Eq,
        Opc::Ne,
        Opc::ULt,
        Opc::ULe,
        Opc::SLt,
        Opc::SLe,
        Opc::TestZ,
        Opc::TestNZ,
        Opc::Ite,
        Opc::Flags,
        Opc::Cond,
        Opc::FlagsSel,
        Opc::FlagsGet,
        Opc::FlagsSet,
    ];
    for opc in Opc::ALL {
        let has_row = ROWS.iter().any(|r| r.0 == *opc && r.6.is_ok());
        assert_eq!(
            has_row,
            data.contains(opc),
            "{opc} has a good row exactly when it is data"
        );
    }
}

#[test]
fn eval_never_panics_on_any_width() {
    for opc in Opc::ALL {
        for w in [0, 1, 7, 8, 9, 63, 64, 65, 127, 128, 129, 255] {
            for sub in [0, 1, 8, 64, 128, 200] {
                for (x, y, z) in [(0, 0, 0), (u128::MAX, u128::MAX, u128::MAX), (TOP, 1, 255)] {
                    let _result = eval(*opc, w, sub, x, y, z);
                }
            }
        }
    }
}

#[test]
fn opcode_codes_and_names() {
    for (i, opc) in Opc::ALL.iter().enumerate() {
        let code = u8::try_from(i).unwrap_or(u8::MAX);
        assert_eq!(Opc::from_code(code), Some(*opc));
        assert_eq!(*opc as u8, code);
        assert!(!opc.name().is_empty());
    }
    assert_eq!(Opc::from_code(250), None);
    assert_eq!(Opc::ALL.len(), 58);
    for (i, op) in FlagOp::ALL.iter().enumerate() {
        assert_eq!(usize::from(op.code()), i);
        assert_eq!(FlagOp::from_code(op.code()), Some(*op));
    }
    assert_eq!(FlagOp::from_code(17), None);
    assert!(Opc::Eq.is_compare() && !Opc::Ite.is_compare());
    assert!(Opc::CJump.is_flow() && !Opc::Store.is_flow());
    assert!(Opc::Get.has_out() && !Opc::Put.has_out() && Opc::Phi.has_out());
}
