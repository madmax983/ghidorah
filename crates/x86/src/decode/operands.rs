//! The operand builder: turns the specs of a table row into operand slots.

use crate::error::{DecodeError, InvalidReason};
use crate::insn::{Encoding, Insn, NO_REG, Slot, tag};
use crate::len::Layout;
use crate::operand::Access;
use crate::regs::{Reg, Seg};
use crate::tables::ops::{K, S, Spec};

/// The extensions of the register fields: values to add to the `reg`, SIB `index` and
/// `rm` or `base` numbers.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Ext {
    pub(crate) r: u8,
    pub(crate) x: u8,
    pub(crate) b: u8,
}

impl Ext {
    /// Gives the extensions of a REX or REX2 prefix.
    pub(crate) fn of_rex(lay: &Layout) -> Self {
        let bit = |v: u8, n: u8| ((v >> n) & 1) << 3;
        match lay.enc {
            Encoding::Rex2 => {
                let p = lay.payload[0];
                Self {
                    r: bit(p, 2) | (bit(p, 6) << 1),
                    x: bit(p, 1) | (bit(p, 5) << 1),
                    b: bit(p, 0) | (bit(p, 4) << 1),
                }
            }
            _ => Self {
                r: bit(lay.rex, 2),
                x: bit(lay.rex, 1),
                b: bit(lay.rex, 0),
            },
        }
    }

    /// Gives the `index` and `base` extensions of a VEX or XOP prefix. The prefix stores these bits in inverted form.
    pub(crate) const fn of_vex(lay: &Layout) -> Self {
        match lay.enc {
            Encoding::Vex3 | Encoding::Xop => {
                let p = !lay.payload[0];
                Self {
                    r: 0,
                    x: ((p >> 6) & 1) << 3,
                    b: ((p >> 5) & 1) << 3,
                }
            }
            _ => Self { r: 0, x: 0, b: 0 },
        }
    }
}

/// The decode context of one instruction.
pub(crate) struct Ctx<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) lay: &'a Layout,
    /// The `v` operand size in bytes.
    pub(crate) osz: u8,
    /// The number of bytes of the first immediate.
    pub(crate) first_imm: u8,
    /// A REX or REX2 prefix is present, so byte registers 4 to 7 are `spl` to `dil`.
    pub(crate) rex_any: bool,
    /// The extensions of the register fields.
    pub(crate) ext: Ext,
}

/// Reads `n` little-endian bytes at `off`. Missing bytes read as zero.
pub(crate) fn le(bytes: &[u8], off: u8, n: u8) -> u64 {
    (0..n).rev().fold(0, |acc, i| {
        let at = usize::from(off).saturating_add(usize::from(i));
        (acc << 8) | u64::from(bytes.get(at).copied().unwrap_or(0))
    })
}

/// Sign-extends the low `n` bytes of `v`.
pub(crate) fn sext(v: u64, n: u8) -> i64 {
    let b = v.to_le_bytes();
    match n {
        1 => i64::from(i8::from_le_bytes([b[0]])),
        2 => i64::from(i16::from_le_bytes([b[0], b[1]])),
        4 => i64::from(i32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        _ => i64::from_le_bytes(b),
    }
}

impl Ctx<'_> {
    fn modrm(&self) -> (u8, u8, u8) {
        let m = self.lay.modrm.unwrap_or(0);
        (m >> 6, (m >> 3) & 7, m & 7)
    }

    /// Tells if `ModRM` `rm` selects memory.
    pub(crate) fn rm_is_mem(&self) -> bool {
        self.lay.modrm.is_some_and(|m| m >> 6 != 3)
    }

    fn zsz(&self) -> u8 {
        if self.lay.osz16() { 2 } else { 4 }
    }

    /// Gives the size in bytes of a size code. `mem` tells if the operand is memory.
    pub(crate) fn size(&self, s: S, mem: bool) -> u8 {
        if mem && matches!(s, S::WV | S::WD) {
            return 2;
        }
        match s {
            S::U0 => 0,
            S::B => 1,
            S::W => 2,
            S::D | S::WD => 4,
            S::Q => 8,
            S::V | S::WV => self.osz,
            S::Z => self.zsz(),
            S::Y => {
                if self.lay.w() {
                    8
                } else {
                    4
                }
            }
            S::X => 16,
            S::T => 10,
            S::P => {
                if self.lay.osz16() {
                    4
                } else {
                    6
                }
            }
        }
    }

    /// Makes a general-purpose register of `size` bytes.
    fn gpr(&self, n: u8, size: u8) -> Reg {
        if size == 1 && !self.rex_any && (4..8).contains(&n) {
            Reg::high_byte(n - 4)
        } else {
            Reg::gpr(n, u16::from(size.max(1)) * 8)
        }
    }

    /// Fills the memory form of `ModRM` `rm` into `out`.
    pub(crate) fn mem(&self, out: &mut Insn, vsib: bool) {
        let (md, _, rm) = self.modrm();
        let aw: u16 = if self.lay.pfx.asz { 32 } else { 64 };
        let (base, index, scale) = if let Some(sib) = self.lay.sib {
            let idx = ((sib >> 3) & 7) | self.ext.x;
            let base_f = sib & 7;
            let index = if vsib {
                Some(Reg::xmm(idx))
            } else if idx == 4 {
                None
            } else {
                Some(Reg::gpr(idx, aw))
            };
            let base = if base_f == 5 && md == 0 {
                None
            } else {
                Some(Reg::gpr(base_f | self.ext.b, aw))
            };
            (base, index, sib >> 6)
        } else if md == 0 && rm == 5 {
            (Some(if aw == 32 { Reg::EIP } else { Reg::RIP }), None, 0)
        } else {
            (Some(Reg::gpr(rm | self.ext.b, aw)), None, 0)
        };
        out.base = base.map_or(NO_REG, Reg::bits);
        out.index = index.map_or(NO_REG, Reg::bits);
        out.memfmt = (out.memfmt & !3) | scale;
        let d = self.lay.disp_size;
        out.disp = sext(le(self.bytes, self.lay.disp_off, d), d);
    }

    fn reg_slot(reg: Reg, access: Access) -> Slot {
        Slot {
            tag: tag::REG | ((access as u8) << 4),
            size: u8::try_from(reg.width_bytes()).unwrap_or(0),
            reg: reg.bits(),
        }
    }

    fn mem_slot(&self, out: &mut Insn, kind: u8, size: u8, access: Access) -> Slot {
        if kind == tag::MEM {
            self.mem(out, false);
        }
        Slot {
            tag: kind | ((access as u8) << 4),
            size,
            reg: 0,
        }
    }

    /// Builds the operand of `spec` and writes the memory and immediate fields of `out`.
    pub(crate) fn operand(
        &self,
        spec: Spec,
        access: Access,
        out: &mut Insn,
    ) -> Result<Slot, DecodeError> {
        let (_, reg, rm) = self.modrm();
        let mem = self.rm_is_mem();
        let size = self.size(spec.s, mem);
        let bad = |reason| DecodeError::Invalid {
            len_consumed: self.lay.len,
            reason,
        };
        let a = access;
        Ok(match spec.k {
            K::None => Slot::default(),
            K::E | K::W | K::Q | K::M if mem => self.mem_slot(out, tag::MEM, size, a),
            K::M => return Err(bad(InvalidReason::RegisterForm)),
            K::U | K::N if mem => return Err(bad(InvalidReason::MemoryForm)),
            K::E | K::R => Self::reg_slot(self.gpr(rm | self.ext.b, size), a),
            K::G => Self::reg_slot(self.gpr(reg | self.ext.r, size), a),
            K::Z => Self::reg_slot(self.gpr((self.lay.opcode & 7) | self.ext.b, size), a),
            K::Acc => Self::reg_slot(self.gpr(0, size), a),
            K::Cl => Self::reg_slot(Reg::gpr(1, 8), a),
            K::Dx => Self::reg_slot(Reg::gpr(2, 16), a),
            K::V => Self::reg_slot(Reg::xmm(reg | self.ext.r), a),
            K::W | K::U => Self::reg_slot(Reg::xmm(rm | self.ext.b), a),
            K::P => Self::reg_slot(Reg::mmx(reg), a),
            K::Q | K::N => Self::reg_slot(Reg::mmx(rm), a),
            K::Sti => Self::reg_slot(Reg::st(rm), a),
            K::Cr => Self::reg_slot(Reg::cr(reg | self.ext.r), a),
            K::Dr => Self::reg_slot(Reg::dr(reg | self.ext.r), a),
            K::Sw => {
                let seg = Seg::from_number(reg).ok_or_else(|| bad(InvalidReason::Undefined))?;
                Self::reg_slot(seg.reg(), a)
            }
            K::Fs => Self::reg_slot(Seg::Fs.reg(), a),
            K::Gs => Self::reg_slot(Seg::Gs.reg(), a),
            K::St0 => Slot {
                tag: tag::ST0 | ((a as u8) << 4),
                size: 10,
                reg: Reg::ST0.bits(),
            },
            K::X => self.mem_slot(out, tag::STR_SRC, size, a),
            K::Y => self.mem_slot(out, tag::STR_DST, size, a),
            K::Xlat => self.mem_slot(out, tag::XLAT, 1, a),
            K::O => {
                let n = self.lay.imm_size;
                out.disp = le(self.bytes, self.lay.imm_off, n).cast_signed();
                self.mem_slot(out, tag::MOFFS, size, a)
            }
            K::I => {
                out.imm = le(self.bytes, self.lay.imm_off, self.first_imm).cast_signed();
                Slot {
                    tag: tag::IMM,
                    size,
                    reg: 0,
                }
            }
            K::Is => {
                let raw = le(self.bytes, self.lay.imm_off, self.first_imm);
                out.imm = sext(raw, self.first_imm);
                let width = self.osz;
                let signed = if self.first_imm < width {
                    tag::SIGNED
                } else {
                    0
                };
                Slot {
                    tag: tag::IMM | signed,
                    size: width,
                    reg: 0,
                }
            }
            K::I2 => {
                let off = self.lay.imm_off.saturating_add(self.first_imm);
                out.imm2 = self.bytes.get(usize::from(off)).copied().unwrap_or(0);
                Slot {
                    tag: tag::IMM2,
                    size: 1,
                    reg: 0,
                }
            }
            K::One => Slot {
                tag: tag::ONE,
                size: 1,
                reg: 0,
            },
            K::J => {
                let raw = le(self.bytes, self.lay.imm_off, self.first_imm);
                out.imm = sext(raw, self.first_imm);
                Slot {
                    tag: tag::TARGET,
                    size: self.first_imm,
                    reg: 0,
                }
            }
        })
    }
}
