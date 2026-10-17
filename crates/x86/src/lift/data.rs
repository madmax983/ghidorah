//! The `mov`, `movx`, `lea`, `cmov`, `setcc` and `stack` templates.

use ghidorah_ir::{Arg, Loc, Opc};

use super::Row;
use super::ctx::{Cx, Fail, Res};
use crate::{Mnem, Operand};

/// Gives the condition code of a mnemonic in a block of 16 that starts at `first`.
pub(super) fn cc_of(m: Mnem, first: Mnem) -> u8 {
    u8::try_from((m as u16).wrapping_sub(first as u16) & 15).unwrap_or(0)
}

/// `mov` and `movabs`.
pub(super) fn mov(cx: &mut Cx<'_>) -> Res<()> {
    let dst = cx.place(0)?;
    let v = cx.operand(1, dst.width())?;
    cx.write(dst, v)
}

/// `movzx`, `movsx` and `movsxd`.
pub(super) fn movx(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let (wd, ws) = (cx.width(0), cx.width(1));
    let dst = cx.place(0)?;
    let v = cx.operand(1, ws)?;
    let res = cx.resize(v, ws, wd, row.mnem != Mnem::Movzx)?;
    cx.write(dst, res)
}

/// `lea`: the address without a segment base, cut to the destination width.
pub(super) fn lea(cx: &mut Cx<'_>) -> Res<()> {
    let Some(Operand::Mem(m)) = cx.insn.op(1) else {
        return Err(Fail::Operand);
    };
    let dst = cx.place(0)?;
    let addr = cx.addr(&m, false)?;
    let res = cx.resize(addr, 64, dst.width(), false)?;
    cx.write(dst, res)
}

/// The 16 `cmovcc` forms. A 32-bit form writes its register in both cases, so the upper
/// bits become zero, as the hardware does.
pub(super) fn cmov(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let w = cx.width(0);
    let dst = cx.place(0)?;
    let src = cx.operand(1, w)?;
    let c = cx.cond(cc_of(row.mnem, Mnem::Cmovo))?;
    let old = cx.read(dst)?;
    let res = cx.op(Opc::Ite, w, 0, [c, src, old])?;
    cx.write(dst, res)
}

/// The 16 `setcc` forms.
pub(super) fn setcc(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let dst = cx.place(0)?;
    let c = cx.cond(cc_of(row.mnem, Mnem::Seto))?;
    let res = cx.resize(c, 1, 8, false)?;
    cx.write(dst, res)
}

/// Pushes a value of `w` bits.
fn push_value(cx: &mut Cx<'_>, v: Arg, w: u8) -> Res<()> {
    let sp = cx.get(Loc::RSP)?;
    let n = cx.bin(Opc::Sub, 64, sp, Arg::k(u64::from(w / 8)))?;
    cx.b.store(w, n, v)?;
    cx.put(Loc::RSP, n)
}

/// `push`, `pop`, `leave`, `pushf` and `popf`.
pub(super) fn stack(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    match row.mnem {
        Mnem::Push => {
            let w = cx.width(0);
            let v = cx.operand(0, w)?;
            push_value(cx, v, w)
        }
        Mnem::Pop => {
            let w = cx.width(0);
            let sp = cx.get(Loc::RSP)?;
            let v = Arg::V(cx.b.load(w, sp)?);
            let n = cx.bin(Opc::Add, 64, sp, Arg::k(u64::from(w / 8)))?;
            cx.put(Loc::RSP, n)?;
            // The address of a memory destination uses the new stack pointer.
            let dst = cx.place(0)?;
            cx.write(dst, v)
        }
        Mnem::Leave => {
            let bp = cx.get(Loc::RBP)?;
            let v = Arg::V(cx.b.load(64, bp)?);
            let n = cx.bin(Opc::Add, 64, bp, Arg::k(8))?;
            cx.put(Loc::RSP, n)?;
            cx.put(Loc::RBP, v)
        }
        Mnem::Pushf => {
            let fl = cx.flags()?;
            let v = cx.un(Opc::FlagsGet, 64, fl)?;
            // Bit 1 is always 1, and IF is 1 in user mode.
            let word = cx.bin(Opc::Or, 64, v, Arg::k(0x202))?;
            push_value(cx, word, 64)
        }
        _ => {
            let sp = cx.get(Loc::RSP)?;
            let v = Arg::V(cx.b.load(64, sp)?);
            let n = cx.bin(Opc::Add, 64, sp, Arg::k(8))?;
            cx.put(Loc::RSP, n)?;
            let f = cx.un(Opc::FlagsSet, 16, v)?;
            cx.put(Loc::Flags, f)
        }
    }
}
