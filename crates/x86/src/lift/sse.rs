//! The `sse_move` and `sse_zero` templates (design Section 6.3, AC-208).
//!
//! A load is a `Load` of 128, 64 or 32 bits. A store is a `Store` of the same width. A
//! register move is a `Copy`. A scalar load and `movd` or `movq` into a register zero the
//! upper bits. `movss` and `movsd` between registers keep the upper bits.

use ghidorah_ir::{Arg, Opc};

use super::Row;
use super::ctx::{Cx, Fail, Place, Res, mem_ok, reg_ok};
use crate::{Mnem, Operand, RegClass};

/// Gives the move width of a row: 32, 64 or 128 bits.
const fn move_width(m: Mnem) -> u8 {
    match m {
        Mnem::Movd | Mnem::Movss => 32,
        Mnem::Movq | Mnem::Movsd => 64,
        _ => 128,
    }
}

/// Tells if an operand is an XMM register.
fn is_xmm(op: Option<Operand>) -> bool {
    matches!(op, Some(Operand::Reg { reg, .. }) if reg.class() == RegClass::Xmm)
}

/// Tells if the template lifts the operands of a move.
pub(super) fn move_fits(insn: &crate::Insn) -> bool {
    let w = move_width(insn.mnem());
    let ok = |op: Option<Operand>| match op {
        Some(Operand::Reg { reg, .. }) => {
            reg_ok(reg, true)
                && (reg.class() == RegClass::Xmm || (w < 128 && reg.width_bits() == u16::from(w)))
        }
        Some(Operand::Mem(m)) => mem_ok(&m) && m.seg.is_none_or(crate::Seg::has_base),
        _ => false,
    };
    insn.n_ops() == 2
        && ok(insn.op(0))
        && ok(insn.op(1))
        && (is_xmm(insn.op(0)) || is_xmm(insn.op(1)))
}

/// Tells if the template lifts a zeroing form: one XMM register for both operands.
pub(super) fn zero_fits(insn: &crate::Insn) -> bool {
    match (insn.op(0), insn.op(1)) {
        (Some(Operand::Reg { reg: lhs, .. }), Some(Operand::Reg { reg: b, .. })) => {
            lhs.class() == RegClass::Xmm && lhs == b && lhs.number() < 32
        }
        _ => false,
    }
}

/// The SSE moves.
pub(super) fn sse_move(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let w = move_width(row.mnem);
    let dst = cx.place(0)?;
    let src = cx.place(1)?;
    let scalar_merge = matches!(row.mnem, Mnem::Movss | Mnem::Movsd);
    match (dst, src) {
        (Place::Xmm { loc }, Place::Xmm { loc: from }) if w == 128 => {
            let v = cx.get(from)?;
            let c = cx.un(Opc::Copy, 128, v)?;
            cx.put(loc, c)
        }
        (Place::Xmm { loc }, Place::Xmm { loc: from }) if scalar_merge => {
            let old = cx.get(loc)?;
            let v = cx.get(from)?;
            let low = cx.un(Opc::Trunc, w, v)?;
            let res = Arg::V(cx.b.insert(128, old, low, w, 0)?);
            cx.put(loc, res)
        }
        (Place::Xmm { loc }, src) => {
            let v = match src {
                Place::Xmm { loc: from } => {
                    let x = cx.get(from)?;
                    cx.un(Opc::Trunc, w, x)?
                }
                Place::Mem { addr, .. } => Arg::V(cx.b.load(w, addr)?),
                Place::Gpr { .. } => cx.read(src)?,
            };
            let res = cx.resize(v, w, 128, false)?;
            cx.put(loc, res)
        }
        (dst, Place::Xmm { loc: from }) => {
            let x = cx.get(from)?;
            let v = cx.resize(x, 128, w, false)?;
            match dst {
                Place::Mem { addr, .. } => Ok(cx.b.store(w, addr, v)?),
                _ => cx.write(dst, v),
            }
        }
        _ => Err(Fail::Operand),
    }
}

/// `pxor`, `xorps` and `xorpd` with one register: the register becomes 0.
pub(super) fn sse_zero(cx: &mut Cx<'_>) -> Res<()> {
    match cx.place(0)? {
        Place::Xmm { loc } => cx.put(loc, Arg::k(0)),
        _ => Err(Fail::Operand),
    }
}
