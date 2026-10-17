//! The decoded instruction (design Section 5.3).
//!
//! [`Insn`] is a compact record of at most 64 bytes (AC-067). It keeps one memory
//! address form, two immediates and four operand slots. [`Insn::op`] builds an
//! [`Operand`] from these fields.

pub use crate::fields::{Encoding, Map, OpaqueForm, PrefixSet, RawFields};
use crate::flags::FlagSet;
use crate::flow::Flow;
use crate::implicit;
use crate::operand::{Access, Mem, Operand};
use crate::regs::{Reg, RegSet, Seg};
use crate::tables::flagtab;
use crate::tables::mnem::Mnem;

/// The operand slot tags.
pub(crate) mod tag {
    pub(crate) const REG: u8 = 1;
    pub(crate) const IMM: u8 = 2;
    pub(crate) const IMM2: u8 = 3;
    pub(crate) const ONE: u8 = 4;
    pub(crate) const MEM: u8 = 5;
    pub(crate) const MOFFS: u8 = 6;
    pub(crate) const STR_SRC: u8 = 7;
    pub(crate) const STR_DST: u8 = 8;
    pub(crate) const XLAT: u8 = 9;
    pub(crate) const TARGET: u8 = 10;
    pub(crate) const OPAQUE: u8 = 11;
    pub(crate) const ST0: u8 = 12;
    /// The immediate is sign-extended.
    pub(crate) const SIGNED: u8 = 1 << 6;
    /// The target is absolute, not relative to the next instruction.
    pub(crate) const ABS: u8 = 1 << 7;
}

/// One operand slot: a tag with the access in bits 4 and 5, a size in bytes and a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct Slot {
    pub(crate) tag: u8,
    pub(crate) size: u8,
    pub(crate) reg: u16,
}

impl Slot {
    pub(crate) const fn kind(self) -> u8 {
        self.tag & 0xf
    }

    pub(crate) const fn access(self) -> Access {
        Access::from_bits(self.tag >> 4)
    }
}

/// The value of `base` and `index` when the register is absent.
pub(crate) const NO_REG: u16 = u16::MAX;

/// A decoded instruction (design Section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Insn {
    pub(crate) addr: u64,
    pub(crate) imm: i64,
    pub(crate) disp: i64,
    pub(crate) slots: [Slot; 4],
    pub(crate) base: u16,
    pub(crate) index: u16,
    pub(crate) mnem: Mnem,
    pub(crate) pfx: PrefixSet,
    pub(crate) len: u8,
    pub(crate) n_ops: u8,
    pub(crate) flow: Flow,
    pub(crate) map: Map,
    pub(crate) enc: Encoding,
    pub(crate) opcode: u8,
    pub(crate) modrm: u8,
    pub(crate) sib: u8,
    pub(crate) rex: u8,
    /// Bits 0 and 1: log2 of the scale. Bits 2 to 4: the segment override plus 1.
    /// Bit 5: 32-bit addresses.
    pub(crate) memfmt: u8,
    pub(crate) imm2: u8,
    /// The displacement offset in bits 4 to 7 and its size in bits 0 to 3.
    pub(crate) disp_at: u8,
    /// The immediate offset in bits 4 to 7 and its size in bits 0 to 3.
    pub(crate) imm_at: u8,
    /// The opcode offset in bits 0 to 3. Bit 4: a `ModRM` byte. Bit 5: a SIB byte.
    pub(crate) hdr: u8,
}

/// The operands of an instruction, in order.
#[derive(Debug, Clone)]
pub struct Ops<'a> {
    insn: &'a Insn,
    next: u8,
}

impl Iterator for Ops<'_> {
    type Item = Operand;

    fn next(&mut self) -> Option<Operand> {
        let op = self.insn.op(usize::from(self.next))?;
        self.next = self.next.saturating_add(1);
        Some(op)
    }
}

impl Insn {
    /// Gives the address of the first byte.
    #[must_use]
    pub const fn addr(&self) -> u64 {
        self.addr
    }

    /// Gives the length in bytes, 1 to 15.
    #[must_use]
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// Tells if the length is zero. A decoded instruction is never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Gives the address after the instruction.
    #[must_use]
    pub const fn next_addr(&self) -> u64 {
        self.addr.wrapping_add(self.len as u64)
    }

    /// Gives the canonical mnemonic.
    #[must_use]
    pub const fn mnem(&self) -> Mnem {
        self.mnem
    }

    /// Gives the control flow kind.
    #[must_use]
    pub const fn flow(&self) -> Flow {
        self.flow
    }

    /// Gives the number of operands, 0 to 4.
    #[must_use]
    pub const fn n_ops(&self) -> u8 {
        self.n_ops
    }

    /// Gives the operands in order.
    #[must_use]
    pub const fn ops(&self) -> Ops<'_> {
        Ops {
            insn: self,
            next: 0,
        }
    }

    /// Gives the prefixes.
    #[must_use]
    pub const fn prefixes(&self) -> PrefixSet {
        self.pfx
    }

    /// Gives the last segment override prefix.
    #[must_use]
    pub const fn seg_override(&self) -> Option<Seg> {
        match (self.memfmt >> 2) & 7 {
            0 => None,
            n => Seg::from_number(n - 1),
        }
    }

    /// Gives the encoding family.
    #[must_use]
    pub const fn encoding(&self) -> Encoding {
        self.enc
    }

    /// Tells if the instruction is an opaque form with the mnemonic `(vector)`.
    #[must_use]
    pub fn is_opaque(&self) -> bool {
        self.mnem == Mnem::Vector
    }

    /// Gives the identity of an opaque form.
    #[must_use]
    pub fn opaque(&self) -> Option<OpaqueForm> {
        self.is_opaque().then_some(OpaqueForm {
            encoding: self.enc,
            map: self.map,
            opcode: self.opcode,
            len: self.len,
        })
    }

    /// Gives the raw encoding fields.
    #[must_use]
    pub const fn raw(&self) -> RawFields {
        let modrm = if self.hdr & 0x10 != 0 {
            Some(self.modrm)
        } else {
            None
        };
        let sib = if self.hdr & 0x20 != 0 {
            Some(self.sib)
        } else {
            None
        };
        RawFields {
            encoding: self.enc,
            map: self.map,
            opcode_off: self.hdr & 0xf,
            opcode: self.opcode,
            rex: if self.pfx.rex() { Some(self.rex) } else { None },
            modrm,
            sib,
            disp_off: self.disp_at >> 4,
            disp_size: self.disp_at & 0xf,
            imm_off: self.imm_at >> 4,
            imm_size: self.imm_at & 0xf,
        }
    }

    pub(crate) fn slot(&self, i: usize) -> Option<Slot> {
        if i >= usize::from(self.n_ops) {
            return None;
        }
        self.slots.get(i).copied()
    }

    pub(crate) const fn addr32(&self) -> bool {
        self.memfmt & 0x20 != 0
    }

    pub(crate) const fn addr_width(&self) -> u8 {
        if self.addr32() { 32 } else { 64 }
    }

    pub(crate) const fn scale(&self) -> u8 {
        1 << (self.memfmt & 3)
    }

    /// Gives the operand at `i`.
    #[must_use]
    pub fn op(&self, i: usize) -> Option<Operand> {
        let slot = self.slot(i)?;
        let access = slot.access();
        Some(match slot.kind() {
            tag::REG => Operand::Reg {
                reg: Reg::from_bits(slot.reg)?,
                access,
            },
            tag::ST0 => Operand::Reg {
                reg: Reg::ST0,
                access,
            },
            tag::IMM => Operand::Imm {
                value: self.imm,
                width: slot.size,
                signed: slot.tag & tag::SIGNED != 0,
            },
            tag::IMM2 => Operand::Imm {
                value: i64::from(self.imm2),
                width: 1,
                signed: false,
            },
            tag::ONE => Operand::Imm {
                value: 1,
                width: 1,
                signed: false,
            },
            tag::TARGET => Operand::Target {
                addr: self.target_of(slot),
            },
            tag::MEM | tag::MOFFS | tag::STR_SRC | tag::STR_DST | tag::XLAT => {
                Operand::Mem(self.mem_of(slot))
            }
            _ => Operand::Opaque,
        })
    }

    fn target_of(&self, slot: Slot) -> u64 {
        if slot.tag & tag::ABS != 0 {
            return self.imm.cast_unsigned();
        }
        let t = self.next_addr().wrapping_add_signed(self.imm);
        if slot.size == 2 { t & 0xffff } else { t }
    }

    fn mask_addr(&self, a: u64) -> u64 {
        if self.addr32() { a & 0xffff_ffff } else { a }
    }

    fn mem_of(&self, slot: Slot) -> Mem {
        let width_bytes = u16::from(slot.size);
        let addr_width = self.addr_width();
        let access = slot.access();
        let gpr = |n: u8| Reg::gpr(n, u16::from(addr_width));
        let implicit = |seg, base, index| Mem {
            seg: Some(seg),
            base: Some(base),
            index,
            scale: 1,
            disp: 0,
            width_bytes,
            addr_width,
            abs_target: None,
            access,
        };
        let seg = self.seg_override();
        match slot.kind() {
            tag::STR_SRC => implicit(seg.unwrap_or(Seg::Ds), gpr(6), None),
            tag::STR_DST => implicit(Seg::Es, gpr(7), None),
            tag::XLAT => implicit(seg.unwrap_or(Seg::Ds), gpr(3), Some(Reg::gpr(0, 8))),
            _ => {
                let seg = seg.filter(|s| s.has_base());
                let moffs = slot.kind() == tag::MOFFS;
                let base = if moffs {
                    None
                } else {
                    Reg::from_bits(self.base)
                };
                let index = if moffs {
                    None
                } else {
                    Reg::from_bits(self.index)
                };
                let abs_target = match (base, index, seg) {
                    (Some(b), None, None) if b == Reg::RIP || b == Reg::EIP => {
                        Some(self.mask_addr(self.next_addr().wrapping_add_signed(self.disp)))
                    }
                    (None, None, None) => Some(self.mask_addr(self.disp.cast_unsigned())),
                    _ => None,
                };
                Mem {
                    seg,
                    base,
                    index,
                    scale: if index.is_some() { self.scale() } else { 1 },
                    disp: self.disp,
                    width_bytes,
                    addr_width,
                    abs_target,
                    access,
                }
            }
        }
    }

    /// Gives the target of a direct branch or call.
    #[must_use]
    pub fn target(&self) -> Option<u64> {
        self.ops().find_map(|op| match op {
            Operand::Target { addr } => Some(addr),
            _ => None,
        })
    }

    /// Gives the first memory operand.
    #[must_use]
    pub fn mem(&self) -> Option<Mem> {
        self.ops().find_map(|op| match op {
            Operand::Mem(m) => Some(m),
            _ => None,
        })
    }

    /// Gives the full registers that the instruction reads, implicit registers included.
    ///
    /// A write of an 8-bit or 16-bit register also reads its full register, because
    /// the write keeps the other bits. An opaque form gives all general-purpose and
    /// vector registers.
    #[must_use]
    pub fn regs_read(&self) -> RegSet {
        implicit::regs(self).0
    }

    /// Gives the full registers that the instruction writes, implicit registers included.
    ///
    /// An opaque form gives all general-purpose and vector registers.
    #[must_use]
    pub fn regs_written(&self) -> RegSet {
        implicit::regs(self).1
    }

    /// Gives the status flags that the instruction reads.
    #[must_use]
    pub fn flags_read(&self) -> FlagSet {
        flagtab::info(self.mnem).read
    }

    /// Gives the status flags that the instruction can write, undefined flags included.
    #[must_use]
    pub fn flags_written(&self) -> FlagSet {
        flagtab::info(self.mnem).written
    }

    /// Gives the status flags that the instruction leaves undefined.
    #[must_use]
    pub fn flags_undefined(&self) -> FlagSet {
        flagtab::info(self.mnem).undefined
    }

    /// Tells if the instruction does nothing: `nop`, the `66 90` form `xchg ax, ax`,
    /// or a hint `nop` of `0F 19` to `0F 1F`.
    #[must_use]
    pub fn is_nop(&self) -> bool {
        match self.mnem {
            Mnem::Nop => true,
            Mnem::Xchg => self.opcode == 0x90 && self.map == Map::One && !self.pfx.rex(),
            _ => false,
        }
    }
}
