//! The registers that each instruction reads and writes: the explicit operands plus the
//! implicit registers of the Intel SDM instruction pages.
//!
//! An opaque form has no operands, so its encoding fields name its registers (design
//! Section 5.1):
//!
//! | Form | Read | Written |
//! |---|---|---|
//! | VEX `0F 77` (`vzeroupper`, `vzeroall`) | vector registers | vector registers, no flags |
//! | BMI1, BMI2, TBM, `rorx`, `cmpccxadd`, `movbe`, `crc32`, `adcx`, `adox` and other general-register forms | the source fields | the destination fields |
//! | `kmov` and the other mask-register forms | mask registers, a general source field | mask registers, a general destination field |
//! | a vector form with a general register field (`vmovd`, `vpextr*`, `vcvt*2si` and others) | vector registers and the source field | vector registers and the destination field |
//! | another VEX, EVEX, XOP, `0F 38` or `0F 3A` form | vector registers | vector registers |
//! | a REX2 or EVEX map 4 form (APX) | all general and vector registers | all general and vector registers |
//!
//! The fields are `ModRM.reg`, `ModRM.rm` of a register form and `vvvv`. Each form also
//! reads the base and the index of its memory operand, and the implicit registers of its SDM
//! page (`mulx` reads `rdx`, `pcmpestri` reads `rax` and `rdx` and writes `rcx`). No form
//! names `rsp` or `rbp` unless one of its fields holds that register. An APX form can use
//! the implicit registers of its legacy instruction, so it keeps all registers.

use crate::fields::{Encoding, Map, RegFields};
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
        // The padlock register use, from the Centaur padlock programming guide.
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

/// The `ModRM.reg` field of a [`Shape`].
const F_REG: u8 = 1;
/// The `ModRM.rm` field of a register form.
const F_RM: u8 = 2;
/// The `vvvv` field.
const F_V: u8 = 4;

/// The registers of an opaque form outside its general register fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// All vector registers, and the EVEX mask register.
    Vector,
    /// No other register: a general-register form.
    Gpr,
    /// All mask registers.
    Mask,
}

/// The register use of an opaque form: the general register fields that it reads and writes,
/// as sets of [`F_REG`], [`F_RM`] and [`F_V`], its implicit registers and its other registers.
#[derive(Debug, Clone, Copy)]
struct Shape {
    class: Class,
    read: u8,
    write: u8,
    implicit_read: &'static [Reg],
    implicit_write: &'static [Reg],
}

impl Shape {
    const fn of(class: Class, read: u8, write: u8) -> Self {
        Self {
            class,
            read,
            write,
            implicit_read: &[],
            implicit_write: &[],
        }
    }

    const fn implicit(mut self, read: &'static [Reg], write: &'static [Reg]) -> Self {
        self.implicit_read = read;
        self.implicit_write = write;
        self
    }
}

/// A general-register form.
const fn gpr(read: u8, write: u8) -> Shape {
    Shape::of(Class::Gpr, read, write)
}

/// A vector form, with the general register fields `read` and `write`.
const fn vector(read: u8, write: u8) -> Shape {
    Shape::of(Class::Vector, read, write)
}

/// `pcmpestrm`, `pcmpestri`, `pcmpistrm` and `pcmpistri` (`0F 3A 60` to `63`): the
/// explicit-length forms read `rax` and `rdx`, and the index forms write `rcx`.
const fn pcmpstr(op: u8) -> Shape {
    let read: &[Reg] = if op <= 0x61 { &[RAX, RDX] } else { &[] };
    let write: &[Reg] = if op & 1 == 1 { &[RCX] } else { &[] };
    vector(0, 0).implicit(read, write)
}

/// The shape of a VEX or EVEX form. `pp` is the prefix field.
fn vex_shape(evex: bool, map: Map, op: u8, pp: u8) -> Shape {
    let scalar = matches!(pp, 2 | 3);
    match (map, op) {
        (Map::M0F, 0x2a) if scalar => vector(F_RM, 0),
        (Map::M0F, 0x2c | 0x2d) | (Map::Map5, 0x6c | 0x6d) if scalar => vector(0, F_REG),
        (Map::M0F, 0x7b) if evex && scalar => vector(F_RM, 0),
        (Map::M0F, 0x78 | 0x79) if evex && scalar => vector(0, F_REG),
        (Map::M0F, 0x50) => vector(0, F_REG),
        (Map::M0F, 0x6e | 0xc4) | (Map::M0F3A, 0x20 | 0x22) | (Map::Map5, 0x6e) if pp == 1 => {
            vector(F_RM, 0)
        }
        (Map::M0F | Map::Map5, 0x7e) | (Map::M0F3A, 0x14..=0x17) if pp == 1 => vector(0, F_RM),
        (Map::M0F, 0xc5 | 0xd7) if pp == 1 => vector(0, F_REG),
        (Map::M0F, 0xf7) if pp == 1 => vector(0, 0).implicit(&[RDI], &[]),
        (Map::M0F, 0x92) => Shape::of(Class::Mask, F_RM, 0),
        (Map::M0F, 0x93) => Shape::of(Class::Mask, 0, F_REG),
        (Map::M0F, 0x41..=0x4b | 0x90 | 0x91 | 0x98 | 0x99) | (Map::M0F3A, 0x30..=0x33) => {
            Shape::of(Class::Mask, 0, 0)
        }
        (Map::M0F38, 0xf2 | 0xf5 | 0xf7) => gpr(F_RM | F_V, F_REG),
        (Map::M0F38, 0xf3) => gpr(F_RM, F_V),
        (Map::M0F38, 0xf6) => gpr(F_RM, F_REG | F_V).implicit(&[RDX], &[]),
        (Map::M0F38, 0xe0..=0xef) => gpr(F_REG | F_V, F_REG),
        (Map::M0F38, 0x7a..=0x7c) if evex && pp == 1 => vector(F_RM, 0),
        (Map::M0F3A, 0xf0) => gpr(F_RM, F_REG),
        (Map::M0F3A, 0x60..=0x63) => pcmpstr(op),
        (Map::Map5, 0x2a | 0x7b) if pp == 2 => vector(F_RM, 0),
        (Map::Map5, 0x2c | 0x2d | 0x78 | 0x79) if pp == 2 => vector(0, F_REG),
        (Map::Map7, 0xf6 | 0xf8) => vector(F_RM, F_RM),
        _ => vector(0, 0),
    }
}

/// The shape of an XOP form: TBM and LWP use general registers.
fn xop_shape(map: Map, op: u8, grp: u8) -> Shape {
    match (map, op, grp) {
        (Map::Xop9, 0x01 | 0x02, _) => gpr(F_RM, F_V),
        (Map::Xop9, 0x12, 0) => gpr(F_RM, 0),
        (Map::Xop9, 0x12, 1) => gpr(0, F_RM),
        (Map::Xop9, 0x12, _) => gpr(F_RM, F_RM),
        (Map::XopA, 0x10, _) => gpr(F_RM, F_REG),
        (Map::XopA, 0x12, _) => gpr(F_RM | F_V, 0),
        _ => vector(0, 0),
    }
}

/// The shape of a legacy `0F 38` or `0F 3A` form. `md` is `ModRM.mod`.
fn legacy_shape(map: Map, op: u8, pp: u8, md: u8) -> Shape {
    match (map, op) {
        (Map::M0F38, 0xf0 | 0xf1) if pp == 3 => gpr(F_REG | F_RM, F_REG),
        (Map::M0F38, 0xf0) => gpr(0, F_REG),
        (Map::M0F38, 0xf6) if pp != 0 => gpr(F_REG | F_RM, F_REG),
        (Map::M0F38, 0xf8) if md == 3 => gpr(F_REG | F_RM, F_REG | F_RM),
        (Map::M0F38, 0x80..=0x82 | 0xf1 | 0xf5 | 0xf6 | 0xf8 | 0xf9 | 0xfc) => gpr(F_REG, 0),
        (Map::M0F38, 0xfa | 0xfb) => vector(F_RM, F_REG),
        (Map::M0F3A, 0x14..=0x17) => vector(0, F_RM),
        (Map::M0F3A, 0x20 | 0x22) => vector(F_RM, 0),
        (Map::M0F3A, 0x60..=0x63) => pcmpstr(op),
        _ => vector(0, 0),
    }
}

/// Gives the shape of an opaque form, or `None` for an APX form (REX2 or EVEX map 4).
fn shape(insn: &Insn, f: &RegFields) -> Option<Shape> {
    let (map, op) = (insn.map(), insn.opcode());
    let modrm = insn.modrm().unwrap_or(0);
    match insn.encoding() {
        Encoding::Rex2 => None,
        Encoding::Evex if map == Map::Map4 => None,
        Encoding::Vex2 | Encoding::Vex3 => Some(vex_shape(false, map, op, f.pp)),
        Encoding::Evex => Some(vex_shape(true, map, op, f.pp)),
        Encoding::Xop => Some(xop_shape(map, op, (modrm >> 3) & 7)),
        Encoding::Legacy => Some(legacy_shape(map, op, f.pp, modrm >> 6)),
    }
}

/// Tells if a VEX or EVEX form takes a vector index in its SIB byte (VSIB).
fn vsib(insn: &Insn) -> bool {
    let op = insn.opcode();
    insn.map() == Map::M0F38
        && match insn.encoding() {
            Encoding::Vex2 | Encoding::Vex3 => (0x90..=0x93).contains(&op),
            Encoding::Evex => matches!(op, 0x90..=0x93 | 0xa0..=0xa3 | 0xc6 | 0xc7),
            _ => false,
        }
}

/// Gives the mask register `k<n>`. The packing is the one of the register model.
fn mask_reg(n: u8) -> Option<Reg> {
    let class = u16::from(RegClass::Mask as u8);
    Reg::from_bits(u16::from(n & 7) | (3 << 6) | (class << 9))
}

/// Tells if an opaque form reads and writes the flags. Only `vzeroupper` and `vzeroall`
/// (VEX `0F 77`) do not.
pub(crate) fn opaque_flags(insn: &Insn) -> bool {
    let vex = matches!(insn.encoding(), Encoding::Vex2 | Encoding::Vex3);
    !(vex && insn.map() == Map::M0F && insn.opcode() == 0x77)
}

/// Gives the read set and the write set of an opaque form by the rules of the module doc.
fn opaque(insn: &Insn) -> (RegSet, RegSet) {
    let f = insn.reg_fields();
    let Some(shape) = shape(insn, &f) else {
        let all = RegSet::GPR32.union(RegSet::VEC32);
        return (all, all);
    };
    let named = |bits: u8| {
        let mut out = RegSet::EMPTY;
        let fields = [(F_REG, Some(f.reg)), (F_RM, f.rm), (F_V, Some(f.vvvv))];
        for (bit, n) in fields {
            if let Some(n) = n.filter(|_| bits & bit != 0) {
                out.insert(Reg::gpr(n, 64));
            }
        }
        out
    };
    let others = match shape.class {
        Class::Vector => RegSet::VEC32,
        Class::Gpr => RegSet::EMPTY,
        Class::Mask => (0..8).filter_map(mask_reg).collect(),
    };
    let mut read = others
        .union(named(shape.read))
        .union(set(shape.implicit_read));
    let written = others
        .union(named(shape.write))
        .union(set(shape.implicit_write));
    if let Some(b) = f.base {
        read.insert(Reg::gpr(b, 64));
    }
    if let Some(i) = f.index.filter(|_| !vsib(insn)) {
        read.insert(Reg::gpr(i, 64));
    }
    if shape.class == Class::Vector
        && f.mask != 0
        && let Some(k) = mask_reg(f.mask)
    {
        read.insert(k);
    }
    (read, written)
}

/// Gives the read set and the write set of an instruction.
pub(crate) fn regs(insn: &Insn) -> (RegSet, RegSet) {
    if insn.is_opaque() {
        return opaque(insn);
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
