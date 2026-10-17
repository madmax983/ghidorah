//! The `alu2`, `alu1`, `shift` and `muldiv` templates.

use ghidorah_ir::sem::{CF, PF, SF, ZF};
use ghidorah_ir::{Arg, FlagOp, Opc};

use super::Row;
use super::ctx::{Cx, Fail, Place, Res};
use crate::{Mnem, Operand};

/// The 1-bit carry flag of a flags word, extended to `w` bits.
fn carry(cx: &mut Cx<'_>, fl: Arg, w: u8) -> Res<Arg> {
    let cc = ghidorah_ir::Cc::x86(2).ok_or(Fail::Operand)?;
    let c = Arg::V(cx.b.cond(cc, fl)?);
    cx.resize(c, 1, w, false)
}

/// `add`, `or`, `adc`, `sbb`, `and`, `sub`, `xor`, `cmp` and `test`.
pub(super) fn alu2(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let w = cx.width(0);
    let dst = cx.place(0)?;
    let src = cx.operand(1, w)?;
    let lhs = cx.read(dst)?;
    let fop = row.flag_op.ok_or(Fail::Operand)?;
    let carried = matches!(row.mnem, Mnem::Adc | Mnem::Sbb);
    let fl = if carried { cx.flags()? } else { Arg::Nil };
    let res = match row.mnem {
        Mnem::Add => cx.bin(Opc::Add, w, lhs, src)?,
        Mnem::Or => cx.bin(Opc::Or, w, lhs, src)?,
        Mnem::And | Mnem::Test => cx.bin(Opc::And, w, lhs, src)?,
        Mnem::Xor => cx.bin(Opc::Xor, w, lhs, src)?,
        Mnem::Adc => {
            let t = cx.bin(Opc::Add, w, lhs, src)?;
            let c = carry(cx, fl, w)?;
            cx.bin(Opc::Add, w, t, c)?
        }
        Mnem::Sbb => {
            let t = cx.bin(Opc::Sub, w, lhs, src)?;
            let c = carry(cx, fl, w)?;
            cx.bin(Opc::Sub, w, t, c)?
        }
        _ => cx.bin(Opc::Sub, w, lhs, src)?,
    };
    if matches!(row.mnem, Mnem::Or | Mnem::Xor) {
        cx.thunk(fop, w, res, res, Arg::Nil)?;
    } else {
        cx.thunk(fop, w, lhs, src, fl)?;
    }
    if row.writes_dst {
        cx.write(dst, res)?;
    }
    Ok(())
}

/// `inc`, `dec`, `neg` and `not`.
pub(super) fn alu1(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let w = cx.width(0);
    let dst = cx.place(0)?;
    let lhs = cx.read(dst)?;
    let res = match row.mnem {
        Mnem::Inc | Mnem::Dec => {
            let opc = if row.mnem == Mnem::Inc {
                Opc::Add
            } else {
                Opc::Sub
            };
            let res = cx.bin(opc, w, lhs, Arg::k(1))?;
            let fl = cx.flags()?;
            cx.thunk(row.flag_op.ok_or(Fail::Operand)?, w, lhs, Arg::Nil, fl)?;
            res
        }
        Mnem::Neg => {
            let res = cx.un(Opc::Neg, w, lhs)?;
            cx.thunk(FlagOp::X86Neg, w, lhs, Arg::Nil, Arg::Nil)?;
            res
        }
        _ => cx.un(Opc::Not, w, lhs)?,
    };
    cx.write(dst, res)
}

/// The masked count of a shift: operand `i` is an immediate or `cl`.
fn count(cx: &mut Cx<'_>, i: usize, w: u8) -> Res<Arg> {
    let cmask: u64 = if w == 64 { 63 } else { 31 };
    match cx.insn.op(i) {
        Some(Operand::Imm { value, .. }) => Ok(Arg::k(value.cast_unsigned() & cmask)),
        Some(Operand::Reg { .. }) => {
            let c = cx.get(ghidorah_ir::Loc::RCX)?;
            let low = cx.un(Opc::Trunc, 8, c)?;
            cx.bin(Opc::And, 8, low, Arg::k(cmask))
        }
        _ => Err(Fail::Operand),
    }
}

/// `shl`, `shr`, `sar`, `rol`, `ror`, `shld` and `shrd`.
///
/// The thunk keeps the old flags for a masked count of 0, as the hardware does.
pub(super) fn shift(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let w = cx.width(0);
    let dst = cx.place(0)?;
    let lhs = cx.read(dst)?;
    let fop = row.flag_op.ok_or(Fail::Operand)?;
    if matches!(row.mnem, Mnem::Shld | Mnem::Shrd) {
        return double(cx, row, dst, lhs, w);
    }
    let cnt = count(cx, 1, w)?;
    let opc = match row.mnem {
        Mnem::Shl => Opc::Shl,
        Mnem::Shr => Opc::LShr,
        Mnem::Sar => Opc::AShr,
        Mnem::Rol => Opc::Rol,
        _ => Opc::Ror,
    };
    let res = cx.bin(opc, w, lhs, cnt)?;
    let fl = cx.flags()?;
    cx.thunk(fop, w, lhs, cnt, fl)?;
    cx.write(dst, res)
}

/// `shld` and `shrd`. CF comes from the thunk of `shl` or `shr`. ZF, SF and PF come from
/// the result, and OF tells if the sign changes. A masked count of 0 keeps the old flags.
fn double(cx: &mut Cx<'_>, row: Row, dst: Place, lhs: Arg, w: u8) -> Res<()> {
    let fop = row.flag_op.ok_or(Fail::Operand)?;
    let src = cx.operand(1, w)?;
    let cnt = count(cx, 2, w)?;
    let inv = cx.bin(Opc::Sub, 8, Arg::k(u64::from(w)), cnt)?;
    let (up, down) = if row.mnem == Mnem::Shld {
        (
            cx.bin(Opc::Shl, w, lhs, cnt)?,
            cx.bin(Opc::LShr, w, src, inv)?,
        )
    } else {
        (
            cx.bin(Opc::LShr, w, lhs, cnt)?,
            cx.bin(Opc::Shl, w, src, inv)?,
        )
    };
    let res = cx.bin(Opc::Or, w, up, down)?;
    let fl = cx.flags()?;
    let fs = Arg::V(cx.b.flags(fop, w, lhs, cnt, fl)?);
    let fr = Arg::V(cx.b.flags(FlagOp::X86Logic, w, res, res, Arg::Nil)?);
    let changed = cx.bin(Opc::Xor, w, res, lhs)?;
    let top = cx.bin(Opc::LShr, w, changed, Arg::k(u64::from(w) - 1))?;
    let top16 = cx.resize(top, w, 16, false)?;
    let of = cx.bin(Opc::Shl, 16, top16, Arg::k(11))?;
    let result = cx.bin(Opc::And, 16, fr, Arg::k(u64::from(ZF | SF | PF)))?;
    let cf = cx.bin(Opc::And, 16, fs, Arg::k(u64::from(CF)))?;
    let both = cx.bin(Opc::Or, 16, result, cf)?;
    let all = cx.bin(Opc::Or, 16, both, of)?;
    let nonzero = cx.bin(Opc::Ne, 8, cnt, Arg::k(0))?;
    let f = cx.op(Opc::FlagsSel, 16, 0, [nonzero, all, fl])?;
    cx.put(ghidorah_ir::Loc::Flags, f)?;
    cx.write(dst, res)
}

/// `mul`, `imul` with 1, 2 or 3 operands, `div` and `idiv`.
pub(super) fn muldiv(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let w = cx.width(0);
    let signed = matches!(row.mnem, Mnem::Imul | Mnem::Idiv);
    match (row.mnem, cx.insn.n_ops()) {
        (Mnem::Imul, 2 | 3) => {
            let dst = cx.place(0)?;
            let (x, y) = if cx.insn.n_ops() == 2 {
                (cx.read(dst)?, cx.operand(1, w)?)
            } else {
                (cx.operand(1, w)?, cx.operand(2, w)?)
            };
            let res = cx.bin(Opc::Mul, w, x, y)?;
            cx.thunk(FlagOp::X86SMul, w, x, y, Arg::Nil)?;
            cx.write(dst, res)
        }
        (Mnem::Mul | Mnem::Imul, _) => widen(cx, row, w, signed),
        _ => divide(cx, w, signed),
    }
}

/// The one-operand multiply: `rdx:rax = rax * src`, or `ax = al * src` at 8 bits.
fn widen(cx: &mut Cx<'_>, row: Row, w: u8, signed: bool) -> Res<()> {
    let src = cx.operand(0, w)?;
    let lhs = cx.read(Cx::gpr(0, w))?;
    if w == 8 {
        let x = cx.resize(lhs, 8, 16, signed)?;
        let y = cx.resize(src, 8, 16, signed)?;
        let p = cx.bin(Opc::Mul, 16, x, y)?;
        cx.write(Cx::gpr(0, 16), p)?;
    } else {
        let lo = cx.bin(Opc::Mul, w, lhs, src)?;
        let hi_opc = if signed { Opc::SMulHi } else { Opc::UMulHi };
        let hi = cx.bin(hi_opc, w, lhs, src)?;
        cx.write(Cx::gpr(0, w), lo)?;
        cx.write(Cx::gpr(2, w), hi)?;
    }
    cx.thunk(row.flag_op.ok_or(Fail::Operand)?, w, lhs, src, Arg::Nil)?;
    Ok(())
}

/// The divide: `rdx:rax / src`, or `ax / src` at 8 bits. A zero divisor stops the
/// interpreter. The flags stay, because the hardware leaves them undefined.
fn divide(cx: &mut Cx<'_>, w: u8, signed: bool) -> Res<()> {
    let src = cx.operand(0, w)?;
    let (div, rem) = if signed {
        (Opc::SDiv, Opc::SRem)
    } else {
        (Opc::UDiv, Opc::URem)
    };
    if w == 8 {
        let n = cx.read(Cx::gpr(0, 16))?;
        let dv = cx.resize(src, 8, 16, signed)?;
        let q = cx.bin(div, 16, n, dv)?;
        let res = cx.bin(rem, 16, n, dv)?;
        let q8 = cx.un(Opc::Trunc, 8, q)?;
        let r8 = cx.un(Opc::Trunc, 8, res)?;
        cx.write(Cx::gpr(0, 8), q8)?;
        return cx.write(
            Place::Gpr {
                loc: ghidorah_ir::Loc::RAX,
                lo: 8,
                w: 8,
            },
            r8,
        );
    }
    let wide = w.saturating_mul(2);
    let hi = cx.read(Cx::gpr(2, w))?;
    let lo = cx.read(Cx::gpr(0, w))?;
    let hi2 = cx.resize(hi, w, wide, false)?;
    let up = cx.bin(Opc::Shl, wide, hi2, Arg::k(u64::from(w)))?;
    let lo2 = cx.resize(lo, w, wide, false)?;
    let n = cx.bin(Opc::Or, wide, up, lo2)?;
    let dv = cx.resize(src, w, wide, signed)?;
    let q = cx.bin(div, wide, n, dv)?;
    let res = cx.bin(rem, wide, n, dv)?;
    let qw = cx.un(Opc::Trunc, w, q)?;
    let rw = cx.un(Opc::Trunc, w, res)?;
    cx.write(Cx::gpr(0, w), qw)?;
    cx.write(Cx::gpr(2, w), rw)
}
