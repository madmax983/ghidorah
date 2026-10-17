//! The special forms: rows that depend on the operand size, the address size, the
//! `ModRM` byte or the mandatory prefix in ways that the plain tables do not cover.

#![allow(clippy::enum_glob_use, reason = "the rows name many mnemonics")]

use crate::error::{DecodeError, Feature};
use crate::len::Layout;
use crate::tables::mnem::Mnem::{self, *};
use crate::tables::ops::{
    ADDR, AX, D64, EV, Entry, IB, JB, JZ, K, LOCK, M0, MB, MD, MQ, MW, MX, RAX, RQ, RV, RW, RW1,
    RW2, S, ST0, STI, Spec, U, UNDEF, V, W1, ZV, op0, op1, op2,
};
use crate::tables::{s, x87};

/// A resolved special form: the row, and whether it uses the mandatory prefix.
pub(crate) struct Resolved {
    pub(crate) e: Entry,
    pub(crate) col_used: bool,
}

const fn plain(e: Entry) -> Resolved {
    Resolved { e, col_used: false }
}

const fn with_col(e: Entry) -> Resolved {
    Resolved { e, col_used: true }
}

fn unsupported(lay: &Layout) -> DecodeError {
    DecodeError::Unsupported {
        feature: Feature::System,
        len: lay.len,
    }
}

/// The `ModRM` fields `(mod, reg, rm)` of a layout.
fn fields(lay: &Layout) -> (u8, u8, u8) {
    let m = lay.modrm.unwrap_or(0);
    (m >> 6, (m >> 3) & 7, m & 7)
}

/// Picks the mnemonic of the operand size: REX.W, then `66`, then the default.
fn by_size(lay: &Layout, w: Mnem, w16: Mnem, other: Mnem) -> Mnem {
    if lay.w() {
        w
    } else if lay.osz16() {
        w16
    } else {
        other
    }
}

/// Picks the `64` form of a mnemonic when REX.W is set.
fn w64(lay: &Layout, plain: Mnem, wide: Mnem) -> Mnem {
    if lay.w() { wide } else { plain }
}

/// Resolves special form `id`.
pub(crate) fn resolve(id: u8, lay: &Layout) -> Result<Resolved, DecodeError> {
    let (md, reg, _) = fields(lay);
    let mem = md != 3;
    Ok(match id {
        s::NOP90 => nop90(lay),
        s::CBW => plain(op0(by_size(lay, Cdqe, Cbw, Cwde), 0)),
        s::CWD => plain(op0(by_size(lay, Cqo, Cwd, Cdq), 0)),
        s::PUSHF => plain(op0(if lay.osz16() { Pushfw } else { Pushf }, D64)),
        s::POPF => plain(op0(if lay.osz16() { Popfw } else { Popf }, D64)),
        s::IRET => plain(op0(by_size(lay, Iretq, Iretw, Iret), 0)),
        s::X87 => plain(x87_row(lay)),
        s::JRCXZ => plain(op1(if lay.pfx.asz { Jecxz } else { Jrcxz }, JB, 0)),
        s::XABORT if lay.modrm == Some(0xf8) => plain(op1(Xabort, IB, 0)),
        s::XBEGIN if lay.modrm == Some(0xf8) => plain(op1(Xbegin, JZ, 0)),
        s::G7 => group7(lay)?,
        s::HINT18 if mem && reg < 4 => {
            let m = [Prefetchnta, Prefetcht0, Prefetcht1, Prefetcht2];
            plain(op1(
                m.get(usize::from(reg)).copied().unwrap_or(Nop),
                MB,
                ADDR,
            ))
        }
        s::HINT1C if mem && reg == 0 && lay.pfx.column() == 0 => plain(op1(Cldemote, MB, ADDR)),
        s::HINT18 | s::HINT1C => plain(op1(Nop, EV, ADDR)),
        s::HINT1E => hint1e(lay),
        s::MOVLPS12 if mem => plain(op2(Movlps, V, MQ, RW1)),
        s::MOVLPS12 => plain(op2(Movhlps, V, U, RW1)),
        s::MOVHPS16 if mem => plain(op2(Movhps, V, MQ, RW1)),
        s::MOVHPS16 => plain(op2(Movlhps, V, U, RW1)),
        s::G15 => group15(lay)?,
        s::G9 => group9(lay)?,
        s::UNSUP => return Err(unsupported(lay)),
        _ => plain(UNDEF),
    })
}

/// `90`: `xchg r8, rax` with REX.B, `pause` with `F3`, `xchg ax, ax` with `66`, else `nop`.
fn nop90(lay: &Layout) -> Resolved {
    let rex_b = match lay.enc {
        crate::insn::Encoding::Rex2 => lay.payload[0] & 0x11 != 0,
        _ => lay.rex & 1 != 0,
    };
    if rex_b || lay.osz16() {
        plain(op2(Xchg, ZV, RAX, RW2))
    } else if lay.pfx.rep == 0xf3 {
        with_col(op0(Pause, 0))
    } else {
        plain(op0(Nop, 0))
    }
}

/// The x87 row of `D8` to `DF`.
fn x87_row(lay: &Layout) -> Entry {
    let (md, reg, rm) = fields(lay);
    let row = usize::from(lay.opcode.wrapping_sub(0xd8) & 7);
    let r = usize::from(reg);
    if md != 3 {
        let Some(&(m, size)) = x87::MEM.get(row).and_then(|t| t.get(r)) else {
            return UNDEF;
        };
        let s = match size {
            0 => S::U0,
            2 => S::W,
            4 => S::D,
            8 => S::Q,
            10 => S::T,
            _ => return UNDEF,
        };
        let store = matches!(
            m,
            Fst | Fstp | Fist | Fistp | Fisttp | Fbstp | Fnstenv | Fnstcw | Fnsave | Fnstsw
        );
        return op1(m, Spec { k: K::M, s }, if store { W1 } else { 0 });
    }
    let Some(&(m, pat)) = x87::REG.get(row).and_then(|t| t.get(r)) else {
        return UNDEF;
    };
    let _ = rm;
    match pat {
        x87::Pat::St0Sti => op2(m, ST0, STI, RW1),
        x87::Pat::StiSt0 => op2(m, STI, ST0, RW1),
        x87::Pat::Sti => op1(m, STI, 0),
        x87::Pat::Single => {
            let modrm = lay.modrm.unwrap_or(0);
            match x87::SINGLES
                .iter()
                .find(|(op, mb, _)| *op == lay.opcode && *mb == modrm)
            {
                Some(&(_, _, Fnstsw)) => op1(Fnstsw, AX, W1),
                Some(&(_, _, m)) => op0(m, 0),
                None => UNDEF,
            }
        }
        x87::Pat::Bad => UNDEF,
    }
}

/// `0F 01`: descriptor tables, `smsw`, `lmsw`, `invlpg` and the register-only forms.
fn group7(lay: &Layout) -> Result<Resolved, DecodeError> {
    let (md, reg, _) = fields(lay);
    let f3 = lay.pfx.rep == 0xf3;
    if md != 3 {
        let e = match reg {
            0 => op1(Sgdt, M0, W1),
            1 => op1(Sidt, M0, W1),
            2 => op1(Lgdt, M0, 0),
            3 => op1(Lidt, M0, 0),
            4 => op1(Smsw, MW, W1),
            5 if f3 => return Err(unsupported(lay)),
            6 => op1(Lmsw, MW, 0),
            7 => op1(Invlpg, MB, ADDR),
            _ => UNDEF,
        };
        return Ok(plain(e));
    }
    let m = lay.modrm.unwrap_or(0);
    if f3 && matches!(m, 0xe8 | 0xea) {
        return Err(unsupported(lay));
    }
    Ok(plain(match m {
        0xc8 => op0(Monitor, 0),
        0xc9 => op0(Mwait, 0),
        0xca => op0(Clac, 0),
        0xcb => op0(Stac, 0),
        0xd0 => op0(Xgetbv, 0),
        0xd1 => op0(Xsetbv, 0),
        0xd5 => op0(Xend, 0),
        0xd6 => op0(Xtest, 0),
        0xe8 => op0(Serialize, 0),
        0xee => op0(Rdpkru, 0),
        0xef => op0(Wrpkru, 0),
        0xf8 => op0(Swapgs, 0),
        0xf9 => op0(Rdtscp, 0),
        0xe0..=0xe7 => op1(Smsw, RV, W1),
        0xf0..=0xf7 => op1(Lmsw, RW, 0),
        _ => return Err(unsupported(lay)),
    }))
}

/// `F3 0F 1E`: `endbr64`, `endbr32` and `rdssp`. Other forms are hint `nop` forms.
fn hint1e(lay: &Layout) -> Resolved {
    let (md, reg, _) = fields(lay);
    match lay.modrm {
        Some(0xfa) => with_col(op0(Endbr64, 0)),
        Some(0xfb) => with_col(op0(Endbr32, 0)),
        _ if md == 3 && reg == 1 => {
            let m = w64(lay, Rdsspd, Rdsspq);
            let r = if lay.w() {
                RQ
            } else {
                Spec { k: K::R, s: S::D }
            };
            with_col(op1(m, r, W1))
        }
        _ => plain(op1(Nop, EV, ADDR)),
    }
}

/// `0F AE`: state save forms, fences and the base register forms.
fn group15(lay: &Layout) -> Result<Resolved, DecodeError> {
    let (md, reg, _) = fields(lay);
    let col = lay.pfx.column();
    let ry = Spec { k: K::R, s: S::Y };
    if md != 3 {
        return Ok(match (col, reg) {
            (1, 6) => with_col(op1(Clwb, MB, 0)),
            (1, 7) => with_col(op1(Clflushopt, MB, 0)),
            (2, 4) => return Err(unsupported(lay)),
            (_, 0) => plain(op1(w64(lay, Fxsave, Fxsave64), M0, W1)),
            (_, 1) => plain(op1(w64(lay, Fxrstor, Fxrstor64), M0, 0)),
            (_, 2) => plain(op1(Ldmxcsr, MD, 0)),
            (_, 3) => plain(op1(Stmxcsr, MD, W1)),
            (_, 4) => plain(op1(w64(lay, Xsave, Xsave64), M0, W1)),
            (_, 5) => plain(op1(w64(lay, Xrstor, Xrstor64), M0, 0)),
            (_, 6) => plain(op1(w64(lay, Xsaveopt, Xsaveopt64), M0, W1)),
            _ => plain(op1(Clflush, MB, 0)),
        });
    }
    Ok(match (col, reg) {
        (2, 0) => with_col(op1(Rdfsbase, ry, W1)),
        (2, 1) => with_col(op1(Rdgsbase, ry, W1)),
        (2, 2) => with_col(op1(Wrfsbase, ry, 0)),
        (2, 3) => with_col(op1(Wrgsbase, ry, 0)),
        (1..=3, 4..=6) => return Err(unsupported(lay)),
        (_, 5) => plain(op0(Lfence, 0)),
        (_, 6) => plain(op0(Mfence, 0)),
        (_, 7) => plain(op0(Sfence, 0)),
        _ => plain(UNDEF),
    })
}

/// `0F C7`: `cmpxchg8b`, `cmpxchg16b`, the VMX pointer forms and the random numbers.
fn group9(lay: &Layout) -> Result<Resolved, DecodeError> {
    let (md, reg, _) = fields(lay);
    let col = lay.pfx.column();
    if md != 3 {
        return Ok(match (col, reg) {
            (_, 1) if lay.w() => plain(op1(Cmpxchg16b, MX, RW1 | LOCK)),
            (_, 1) => plain(op1(Cmpxchg8b, MQ, RW1 | LOCK)),
            (_, 3) => plain(op1(w64(lay, Xrstors, Xrstors64), M0, 0)),
            (_, 4) => plain(op1(w64(lay, Xsavec, Xsavec64), M0, W1)),
            (_, 5) => plain(op1(w64(lay, Xsaves, Xsaves64), M0, W1)),
            (1, 6) => with_col(op1(Vmclear, MQ, 0)),
            (2, 6) => with_col(op1(Vmxon, MQ, 0)),
            (2 | 3, 7) => return Err(unsupported(lay)),
            (_, 6) => plain(op1(Vmptrld, MQ, 0)),
            (_, 7) => plain(op1(Vmptrst, MQ, W1)),
            _ => plain(UNDEF),
        });
    }
    Ok(match (col, reg) {
        (2, 7) => with_col(op1(Rdpid, RQ, W1)),
        (2 | 3, 6..=7) => return Err(unsupported(lay)),
        (_, 6) => plain(op1(Rdrand, RV, W1)),
        (_, 7) => plain(op1(Rdseed, RV, W1)),
        _ => plain(UNDEF),
    })
}
