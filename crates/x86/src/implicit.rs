//! The registers that each instruction reads and writes: the explicit operands plus the
//! implicit registers of the Intel SDM instruction pages.

use crate::insn::Insn;
use crate::operand::Operand;
use crate::regs::{Reg, RegClass, RegSet};
use crate::tables::mnem::Mnem;

const RAX: Reg = Reg::RAX;
const RCX: Reg = Reg::RCX;
const RDX: Reg = Reg::RDX;
const RBX: Reg = Reg::RBX;
const RSP: Reg = Reg::RSP;
const RBP: Reg = Reg::RBP;
const RSI: Reg = Reg::RSI;
const RDI: Reg = Reg::RDI;

fn set(regs: &[Reg]) -> RegSet {
    regs.iter().copied().collect()
}

/// Gives the width in bytes of the first operand.
fn first_width(insn: &Insn) -> u16 {
    match insn.op(0) {
        Some(Operand::Reg { reg, .. }) => reg.width_bytes(),
        Some(Operand::Mem(m)) => m.width_bytes,
        _ => 0,
    }
}

/// Gives the implicit `(read, write)` registers of an instruction.
fn implicit(insn: &Insn) -> (RegSet, RegSet) {
    use Mnem as M;
    let rep = insn.prefixes().rep() || insn.prefixes().repne();
    let counted = |r: &[Reg], w: &[Reg]| {
        let (mut r, mut w) = (set(r), set(w));
        if rep {
            r.insert(RCX);
            w.insert(RCX);
        }
        (r, w)
    };
    let byte = first_width(insn) == 1;
    match insn.mnem() {
        M::Push
        | M::Pop
        | M::Call
        | M::Ret
        | M::Retf
        | M::Pushf
        | M::Popf
        | M::Pushfw
        | M::Popfw
        | M::Iret
        | M::Iretw
        | M::Iretq
        | M::Erets
        | M::Eretu => (set(&[RSP]), set(&[RSP])),
        // The VIA PadLock register use, from the VIA PadLock programming guide.
        M::XstoreRng => counted(&[RDX, RDI], &[RAX, RDI]),
        M::XcryptEcb | M::XcryptCbc | M::XcryptCtr | M::XcryptCfb | M::XcryptOfb => {
            counted(&[RAX, RBX, RDX, RSI, RDI], &[RAX, RSI, RDI])
        }
        M::Xsha1 | M::Xsha256 => counted(&[RAX, RSI, RDI], &[RAX, RSI]),
        M::Montmul => counted(&[RAX, RSI], &[RAX, RDX]),
        M::Enter | M::Leave => (set(&[RSP, RBP]), set(&[RSP, RBP])),
        M::Mul | M::Imul | M::Div | M::Idiv if insn.n_ops() == 1 => {
            let divide = matches!(insn.mnem(), M::Div | M::Idiv);
            match (byte, divide) {
                (true, _) => (set(&[RAX]), set(&[RAX])),
                (false, false) => (set(&[RAX]), set(&[RAX, RDX])),
                (false, true) => (set(&[RAX, RDX]), set(&[RAX, RDX])),
            }
        }
        M::Cbw | M::Cwde | M::Cdqe | M::Cmpxchg | M::Lahf => (set(&[RAX]), set(&[RAX])),
        M::Cwd | M::Cdq | M::Cqo => (set(&[RAX]), set(&[RDX])),
        M::Cmpxchg8b | M::Cmpxchg16b => (set(&[RAX, RBX, RCX, RDX]), set(&[RAX, RDX])),
        M::Cpuid => (set(&[RAX, RCX]), set(&[RAX, RBX, RCX, RDX])),
        M::Rdtsc => (RegSet::EMPTY, set(&[RAX, RDX])),
        M::Rdtscp => (RegSet::EMPTY, set(&[RAX, RCX, RDX])),
        M::Rdmsr | M::Rdpmc | M::Xgetbv | M::Rdpkru => (set(&[RCX]), set(&[RAX, RDX])),
        M::Wrmsr | M::Xsetbv | M::Wrpkru | M::Monitor => (set(&[RAX, RCX, RDX]), RegSet::EMPTY),
        M::Mwait => (set(&[RAX, RCX]), RegSet::EMPTY),
        M::Syscall => (
            set(&[RAX, RDI, RSI, RDX, Reg::R10, Reg::R8, Reg::R9]),
            set(&[RAX, RCX, Reg::R11]),
        ),
        M::Sysret => (set(&[RCX, Reg::R11]), RegSet::EMPTY),
        M::Movs | M::Cmps => counted(&[RSI, RDI], &[RSI, RDI]),
        M::Stos | M::Scas | M::Ins => counted(&[RDI], &[RDI]),
        M::Lods | M::Outs => counted(&[RSI], &[RSI]),
        M::Xlat => (set(&[RAX, RBX]), set(&[RAX])),
        M::Sahf => (set(&[RAX]), RegSet::EMPTY),
        M::Loop | M::Loope | M::Loopne => (set(&[RCX]), set(&[RCX])),
        M::Jrcxz | M::Jecxz => (set(&[RCX]), RegSet::EMPTY),
        M::Maskmovq | M::Maskmovdqu => (set(&[RDI]), RegSet::EMPTY),
        _ => (RegSet::EMPTY, RegSet::EMPTY),
    }
}

/// Gives the read set and the write set of an instruction.
pub(crate) fn regs(insn: &Insn) -> (RegSet, RegSet) {
    if insn.is_opaque() {
        let all = RegSet::GPR32.union(RegSet::VEC32);
        return (all, all);
    }
    if insn.mnem() == Mnem::Nop {
        // A hint `nop` does not compute its address.
        return (RegSet::EMPTY, RegSet::EMPTY);
    }
    let (mut read, mut written) = implicit(insn);
    for op in insn.ops() {
        match op {
            Operand::Reg { reg, access } => {
                if access.reads() {
                    read.insert(reg);
                }
                if access.writes() {
                    written.insert(reg);
                    let partial = reg.class() == RegClass::Gpr && reg.width_bits() < 32;
                    if partial {
                        read.insert(reg);
                    }
                }
            }
            Operand::Mem(m) => {
                for r in [m.base, m.index].into_iter().flatten() {
                    if r.class() != RegClass::Ip {
                        read.insert(r);
                    }
                }
            }
            _ => {}
        }
    }
    (read, written)
}
