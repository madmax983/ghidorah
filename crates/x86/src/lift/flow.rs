//! The `branch` and `string` templates.

use ghidorah_ir::{Arg, Cc, Loc, Opc};

use super::Row;
use super::ctx::{Cx, Fail, Res};
use super::data::cc_of;
use crate::Mnem;

/// The condition code `e`.
const CC_E: u8 = 4;

/// The condition code `ne`.
const CC_NE: u8 = 5;

/// Gives the target of a direct branch, or reads the 64-bit operand of an indirect one.
fn target(cx: &mut Cx<'_>) -> Res<(Arg, bool)> {
    match cx.insn.target() {
        Some(t) => Ok((Arg::k(t), true)),
        None => Ok((cx.operand(0, 64)?, false)),
    }
}

/// `jcc`, `jmp`, `call`, `ret`, `loop`, `loope`, `loopne`, `jrcxz` and `jecxz`.
pub(super) fn branch(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let m = row.mnem;
    match m {
        Mnem::Jmp => {
            let (t, direct) = target(cx)?;
            let opc = if direct { Opc::Jump } else { Opc::JumpInd };
            Ok(cx.b.flow(opc, t, Arg::Nil)?)
        }
        Mnem::Call => {
            // An indirect target reads its operand before the push changes `rsp`.
            let (t, direct) = target(cx)?;
            let sp = cx.get(Loc::RSP)?;
            let n = cx.bin(Opc::Sub, 64, sp, Arg::k(8))?;
            cx.b.store(64, n, Arg::k(cx.insn.next_addr()))?;
            cx.put(Loc::RSP, n)?;
            let opc = if direct { Opc::Call } else { Opc::CallInd };
            Ok(cx.b.flow(opc, t, Arg::Nil)?)
        }
        Mnem::Ret => {
            let extra = match cx.insn.op(0) {
                Some(crate::Operand::Imm { value, .. }) => value.cast_unsigned() & 0xffff,
                _ => 0,
            };
            let sp = cx.get(Loc::RSP)?;
            let n = cx.bin(Opc::Add, 64, sp, Arg::k(8 + extra))?;
            cx.put(Loc::RSP, n)?;
            Ok(cx.b.flow(Opc::Ret, Arg::Nil, Arg::Nil)?)
        }
        _ => {
            let c = match m {
                Mnem::Loop | Mnem::Loope | Mnem::Loopne => {
                    let c = cx.get(Loc::RCX)?;
                    let c2 = cx.bin(Opc::Sub, 64, c, Arg::k(1))?;
                    cx.put(Loc::RCX, c2)?;
                    let nz = cx.bin(Opc::Ne, 64, c2, Arg::k(0))?;
                    match m {
                        Mnem::Loope => {
                            let z = cx.cond(CC_E)?;
                            cx.bin(Opc::And, 1, nz, z)?
                        }
                        Mnem::Loopne => {
                            let z = cx.cond(CC_NE)?;
                            cx.bin(Opc::And, 1, nz, z)?
                        }
                        _ => nz,
                    }
                }
                Mnem::Jrcxz => {
                    let c = cx.get(Loc::RCX)?;
                    cx.bin(Opc::Eq, 64, c, Arg::k(0))?
                }
                Mnem::Jecxz => {
                    let c = cx.get(Loc::RCX)?;
                    cx.bin(Opc::Eq, 32, c, Arg::k(0))?
                }
                _ => cx.cond(cc_of(m, Mnem::Jo))?,
            };
            let t = cx.insn.target().ok_or(Fail::Operand)?;
            Ok(cx.b.flow(Opc::CJump, c, Arg::k(t))?)
        }
    }
}

/// Adds `n` to a pointer register.
fn advance(cx: &mut Cx<'_>, loc: Loc, at: Arg, n: u64) -> Res<()> {
    let next = cx.bin(Opc::Add, 64, at, Arg::k(n))?;
    cx.put(loc, next)
}

/// `movs`, `stos`, `lods`, `scas` and `cmps` with `rep`, `repe` or `repne`.
///
/// A `rep` form is a loop on its own address. It leaves when `rcx` is 0. Else it runs the
/// body once and takes 1 from `rcx`. A `cmps` or `scas` form also leaves on the ZF
/// condition of its prefix.
pub(super) fn string(cx: &mut Cx<'_>, row: Row) -> Res<()> {
    let m = row.mnem;
    let w = cx
        .insn
        .mem()
        .and_then(|mem| u8::try_from(mem.width_bytes.saturating_mul(8)).ok())
        .ok_or(Fail::Operand)?;
    let step = u64::from(w / 8);
    let pfx = cx.insn.prefixes();
    let rep = pfx.rep() || pfx.repne();
    let next = Arg::k(cx.insn.next_addr());
    let count = if rep {
        let rcx = cx.get(Loc::RCX)?;
        let done = cx.bin(Opc::Eq, 64, rcx, Arg::k(0))?;
        cx.b.flow(Opc::CJump, done, next)?;
        Some(rcx)
    } else {
        None
    };
    let mut flags = None;
    match m {
        Mnem::Movs => {
            let src = cx.get(Loc::RSI)?;
            let v = Arg::V(cx.b.load(w, src)?);
            let dst = cx.get(Loc::RDI)?;
            cx.b.store(w, dst, v)?;
            advance(cx, Loc::RSI, src, step)?;
            advance(cx, Loc::RDI, dst, step)?;
        }
        Mnem::Stos => {
            let v = cx.read(Cx::gpr(0, w))?;
            let dst = cx.get(Loc::RDI)?;
            cx.b.store(w, dst, v)?;
            advance(cx, Loc::RDI, dst, step)?;
        }
        Mnem::Lods => {
            let src = cx.get(Loc::RSI)?;
            let v = Arg::V(cx.b.load(w, src)?);
            cx.write(Cx::gpr(0, w), v)?;
            advance(cx, Loc::RSI, src, step)?;
        }
        Mnem::Scas => {
            let lhs = cx.read(Cx::gpr(0, w))?;
            let dst = cx.get(Loc::RDI)?;
            let x = Arg::V(cx.b.load(w, dst)?);
            flags = Some(cx.thunk(ghidorah_ir::FlagOp::X86Sub, w, lhs, x, Arg::Nil)?);
            advance(cx, Loc::RDI, dst, step)?;
        }
        _ => {
            let src = cx.get(Loc::RSI)?;
            let x = Arg::V(cx.b.load(w, src)?);
            let dst = cx.get(Loc::RDI)?;
            let y = Arg::V(cx.b.load(w, dst)?);
            flags = Some(cx.thunk(ghidorah_ir::FlagOp::X86Sub, w, x, y, Arg::Nil)?);
            advance(cx, Loc::RSI, src, step)?;
            advance(cx, Loc::RDI, dst, step)?;
        }
    }
    let Some(c) = count else {
        return Ok(());
    };
    let c2 = cx.bin(Opc::Sub, 64, c, Arg::k(1))?;
    cx.put(Loc::RCX, c2)?;
    if let Some(f) = flags {
        // `repe` leaves when ZF is 0, `repne` leaves when ZF is 1.
        let code = if pfx.repne() { CC_E } else { CC_NE };
        let cc = Cc::x86(code).ok_or(Fail::Operand)?;
        let leave = Arg::V(cx.b.cond(cc, f)?);
        cx.b.flow(Opc::CJump, leave, next)?;
    }
    Ok(cx.b.flow(Opc::Jump, Arg::k(cx.insn.addr()), Arg::Nil)?)
}
