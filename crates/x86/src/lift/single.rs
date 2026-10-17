//! The single forms: exchanges, bit operations, counts, sign extensions, flag operations
//! and `nop` forms.

use ghidorah_ir::sem::{CF, OF};
use ghidorah_ir::{Arg, FlagOp, Loc, Opc};

use super::Row;
use super::ctx::{Cx, Fail, Place, Res};
use crate::{Mnem, Operand};

/// The flag bits that `sahf` writes: SF, ZF, AF, PF and CF.
const SAHF_BITS: u64 = 0xd5;

/// The single forms.
pub(super) fn single(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    match row.mnem {
        Mnem::Xchg if cx.insn.is_nop() => nop(cx),
        Mnem::Xchg => xchg(cx),
        Mnem::Cmpxchg => cmpxchg(cx),
        Mnem::Xadd => xadd(cx),
        Mnem::Bswap => {
            let w = cx.width(0);
            let dst = cx.place(0)?;
            let lhs = cx.read(dst)?;
            let res = cx.un(Opc::Bswap, w, lhs)?;
            cx.write(dst, res)
        }
        Mnem::Bt | Mnem::Bts | Mnem::Btr | Mnem::Btc => bit_test(cx, row),
        Mnem::Bsf | Mnem::Bsr => bit_scan(cx, row),
        Mnem::Popcnt | Mnem::Lzcnt | Mnem::Tzcnt => count(cx, row),
        Mnem::Cbw | Mnem::Cwde | Mnem::Cdqe => {
            let w = fixed(row);
            let v = cx.read(Cx::gpr(0, w / 2))?;
            let res = cx.resize(v, w / 2, w, true)?;
            cx.write(Cx::gpr(0, w), res)
        }
        Mnem::Cwd | Mnem::Cdq | Mnem::Cqo => {
            let w = fixed(row);
            let v = cx.read(Cx::gpr(0, w))?;
            let res = cx.bin(Opc::AShr, w, v, Arg::k(u64::from(w) - 1))?;
            cx.write(Cx::gpr(2, w), res)
        }
        Mnem::Lahf => {
            let fl = cx.flags()?;
            let v = cx.un(Opc::FlagsGet, 8, fl)?;
            let bits = cx.bin(Opc::And, 8, v, Arg::k(SAHF_BITS))?;
            let res = cx.bin(Opc::Or, 8, bits, Arg::k(2))?;
            cx.write(ah(), res)
        }
        Mnem::Sahf => {
            let h = cx.read(ah())?;
            let h16 = cx.resize(h, 8, 16, false)?;
            let bits = cx.bin(Opc::And, 16, h16, Arg::k(SAHF_BITS))?;
            let fl = cx.flags()?;
            let keep = cx.bin(Opc::And, 16, fl, Arg::k(u64::from(OF)))?;
            let n = cx.bin(Opc::Or, 16, keep, bits)?;
            let f = cx.un(Opc::FlagsSet, 16, n)?;
            cx.put(Loc::Flags, f)
        }
        Mnem::Cmc | Mnem::Clc | Mnem::Stc => {
            let fl = cx.flags()?;
            let cf = u64::from(CF);
            let f = match row.mnem {
                Mnem::Cmc => cx.bin(Opc::Xor, 16, fl, Arg::k(cf))?,
                Mnem::Clc => cx.bin(Opc::And, 16, fl, Arg::k(0xffff & !cf))?,
                _ => cx.bin(Opc::Or, 16, fl, Arg::k(cf))?,
            };
            cx.put(Loc::Flags, f)
        }
        _ => nop(cx),
    }
}

/// The fixed width of a row.
const fn fixed(row: Row) -> u8 {
    match row.width {
        super::WidthRule::Fixed(w) => w,
        super::WidthRule::Dst => 64,
    }
}

/// The place of `ah`.
const fn ah() -> Place {
    Place::Gpr {
        loc: Loc::RAX,
        lo: 8,
        w: 8,
    }
}

/// A form without an effect: `nop`, `endbr64`, `pause` and `cld`. The direction flag of the
/// lifter is 0 already.
fn nop(cx: &mut Cx<'_>) -> Res<()> {
    Ok(cx.b.flow(Opc::Nop, Arg::Nil, Arg::Nil)?)
}

fn xchg(cx: &mut Cx<'_>) -> Res<()> {
    let p0 = cx.place(0)?;
    let p1 = cx.place(1)?;
    let lhs = cx.read(p0)?;
    let b = cx.read(p1)?;
    cx.write(p0, b)?;
    cx.write(p1, lhs)
}

/// `cmpxchg`: when the accumulator equals the destination, the destination takes the
/// source and the accumulator stays. Else the accumulator takes the destination, and a
/// register destination stays. A memory destination gets a write in both cases.
fn cmpxchg(cx: &mut Cx<'_>) -> Res<()> {
    let w = cx.width(0);
    let dst = cx.place(0)?;
    let acc_place = Cx::gpr(0, w);
    let acc = cx.read(acc_place)?;
    let old = cx.read(dst)?;
    let src = cx.operand(1, w)?;
    cx.thunk(FlagOp::X86Sub, w, acc, old, Arg::Nil)?;
    let eq = cx.bin(Opc::Eq, w, acc, old)?;
    match dst {
        Place::Mem { addr, .. } => {
            let v = cx.op(Opc::Ite, w, 0, [eq, src, old])?;
            cx.b.store(w, addr, v)?;
        }
        Place::Gpr { loc, .. } => {
            let merged = cx.merged(dst, src)?;
            let full = cx.get(loc)?;
            let v = cx.op(Opc::Ite, 64, 0, [eq, merged, full])?;
            cx.put(loc, v)?;
        }
        Place::Xmm { .. } => return Err(Fail::Operand),
    }
    let merged = cx.merged(acc_place, old)?;
    let rax = cx.get(Loc::RAX)?;
    let v = cx.op(Opc::Ite, 64, 0, [eq, rax, merged])?;
    cx.put(Loc::RAX, v)
}

/// `xadd`: the source takes the destination, and the destination takes the sum.
fn xadd(cx: &mut Cx<'_>) -> Res<()> {
    let w = cx.width(0);
    let dst = cx.place(0)?;
    let src = cx.place(1)?;
    let lhs = cx.read(dst)?;
    let b = cx.read(src)?;
    let sum = cx.bin(Opc::Add, w, lhs, b)?;
    cx.thunk(FlagOp::X86Add, w, lhs, b, Arg::Nil)?;
    cx.write(src, lhs)?;
    cx.write(dst, sum)
}

/// `bt`, `bts`, `btr` and `btc`. A memory operand with a register offset addresses a bit
/// string: the word at `addr + (offset >> log2 w) * (w / 8)`.
fn bit_test(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let w = cx.width(0);
    let bits = u64::from(w) - 1;
    let (place, bit) = match (cx.insn.op(0), cx.insn.op(1)) {
        (Some(Operand::Mem(m)), Some(Operand::Reg { .. })) => {
            let off = cx.operand(1, w)?;
            let wide = cx.resize(off, w, 64, true)?;
            let word = cx.bin(Opc::AShr, 64, wide, Arg::k(u64::from(w.trailing_zeros())))?;
            let bytes = cx.bin(
                Opc::Shl,
                64,
                word,
                Arg::k(u64::from((w / 8).trailing_zeros())),
            )?;
            let base = cx.addr(&m, true)?;
            let addr = cx.bin(Opc::Add, 64, base, bytes)?;
            let bit = cx.bin(Opc::And, w, off, Arg::k(bits))?;
            (Place::Mem { addr, w }, bit)
        }
        (_, Some(Operand::Imm { value, .. })) => {
            (cx.place(0)?, Arg::k(value.cast_unsigned() & bits))
        }
        _ => {
            let off = cx.operand(1, w)?;
            let bit = cx.bin(Opc::And, w, off, Arg::k(bits))?;
            (cx.place(0)?, bit)
        }
    };
    let lhs = cx.read(place)?;
    let fl = cx.flags()?;
    cx.thunk(FlagOp::X86Bt, w, lhs, bit, fl)?;
    if row.mnem == Mnem::Bt {
        return Ok(());
    }
    let one = cx.bin(Opc::Shl, w, Arg::k(1), bit)?;
    let res = match row.mnem {
        Mnem::Bts => cx.bin(Opc::Or, w, lhs, one)?,
        Mnem::Btr => {
            let inv = cx.un(Opc::Not, w, one)?;
            cx.bin(Opc::And, w, lhs, inv)?
        }
        _ => cx.bin(Opc::Xor, w, lhs, one)?,
    };
    cx.write(place, res)
}

/// `bsf` and `bsr`. A source of 0 sets ZF and keeps the whole destination register, as
/// the hardware does.
fn bit_scan(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let w = cx.width(0);
    let dst = cx.place(0)?;
    let src = cx.operand(1, w)?;
    let zero = cx.bin(Opc::Eq, w, src, Arg::k(0))?;
    let res = if row.mnem == Mnem::Bsf {
        cx.un(Opc::Ctz, w, src)?
    } else {
        let lead = cx.un(Opc::Clz, w, src)?;
        cx.bin(Opc::Sub, w, Arg::k(u64::from(w) - 1), lead)?
    };
    cx.thunk(FlagOp::X86Logic, w, src, src, Arg::Nil)?;
    let Place::Gpr { loc, .. } = dst else {
        return Err(Fail::Operand);
    };
    let merged = cx.merged(dst, res)?;
    let full = cx.get(loc)?;
    let v = cx.op(Opc::Ite, 64, 0, [zero, full, merged])?;
    cx.put(loc, v)
}

/// `popcnt`, `lzcnt` and `tzcnt`. `popcnt` sets ZF for a source of 0 and clears the other
/// flags. `lzcnt` and `tzcnt` set CF for a source of 0 and ZF for a result of 0.
fn count(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let w = cx.width(0);
    let dst = cx.place(0)?;
    let src = cx.operand(1, w)?;
    let opc = match row.mnem {
        Mnem::Popcnt => Opc::Popcnt,
        Mnem::Lzcnt => Opc::Clz,
        _ => Opc::Ctz,
    };
    let res = cx.un(opc, w, src)?;
    let src_zero = cx.bin(Opc::Eq, w, src, Arg::k(0))?;
    let src16 = cx.resize(src_zero, 1, 16, false)?;
    let f = if row.mnem == Mnem::Popcnt {
        cx.bin(Opc::Shl, 16, src16, Arg::k(6))?
    } else {
        let res_zero = cx.bin(Opc::Eq, w, res, Arg::k(0))?;
        let res16 = cx.resize(res_zero, 1, 16, false)?;
        let zf = cx.bin(Opc::Shl, 16, res16, Arg::k(6))?;
        cx.bin(Opc::Or, 16, src16, zf)?
    };
    cx.put(Loc::Flags, f)?;
    cx.write(dst, res)
}
