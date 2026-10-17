//! The decoded instruction (design Section 5.3).
//!
//! [`Insn`] is a compact record of at most 64 bytes (AC-067). It keeps one memory
//! address form, two immediates and four operand slots. [`Insn::op`] builds an
//! [`Operand`] from these fields.

use crate::flags::FlagSet;
use crate::flow::Flow;
use crate::implicit;
use crate::operand::{Access, Mem, Operand};
use crate::regs::{Reg, RegSet, Seg};
use crate::tables::flagtab;
use crate::tables::mnem::Mnem;

/// The opcode map of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Map {
    /// The one-byte map.
    #[default]
    One = 0,
    /// The `0F` map.
    M0F = 1,
    /// The `0F 38` map.
    M0F38 = 2,
    /// The `0F 3A` map.
    M0F3A = 3,
    /// EVEX map 4 (APX forms of legacy instructions).
    Map4 = 4,
    /// VEX or EVEX map 5.
    Map5 = 5,
    /// VEX or EVEX map 6.
    Map6 = 6,
    /// VEX or EVEX map 7.
    Map7 = 7,
    /// XOP map 8.
    Xop8 = 8,
    /// XOP map 9.
    Xop9 = 9,
    /// XOP map 10.
    XopA = 10,
}

impl Map {
    /// Gives the display name: `map0`, `0f`, `0f38`, `0f3a`, `map4` to `map7`, `xop8`,
    /// `xop9` or `xopa`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::One => "map0",
            Self::M0F => "0f",
            Self::M0F38 => "0f38",
            Self::M0F3A => "0f3a",
            Self::Map4 => "map4",
            Self::Map5 => "map5",
            Self::Map6 => "map6",
            Self::Map7 => "map7",
            Self::Xop8 => "xop8",
            Self::Xop9 => "xop9",
            Self::XopA => "xopa",
        }
    }

    /// Gives the map of a VEX or EVEX map number, 0 to 7.
    #[must_use]
    pub(crate) const fn from_number(n: u8) -> Self {
        match n {
            1 => Self::M0F,
            2 => Self::M0F38,
            3 => Self::M0F3A,
            4 => Self::Map4,
            5 => Self::Map5,
            6 => Self::Map6,
            7 => Self::Map7,
            8 => Self::Xop8,
            9 => Self::Xop9,
            10 => Self::XopA,
            _ => Self::One,
        }
    }
}

/// The encoding family of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Encoding {
    /// Legacy prefixes, an optional REX prefix and an opcode.
    #[default]
    Legacy = 0,
    /// The two-byte APX prefix `D5`.
    Rex2 = 1,
    /// The two-byte VEX prefix `C5`.
    Vex2 = 2,
    /// The three-byte VEX prefix `C4`.
    Vex3 = 3,
    /// The four-byte EVEX prefix `62`.
    Evex = 4,
    /// The three-byte AMD XOP prefix `8F`.
    Xop = 5,
}

impl Encoding {
    /// Gives the stable name, for example `vex3`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Rex2 => "rex2",
            Self::Vex2 => "vex2",
            Self::Vex3 => "vex3",
            Self::Evex => "evex",
            Self::Xop => "xop",
        }
    }
}

/// The identity of an opaque form (design Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpaqueForm {
    /// The encoding family.
    pub encoding: Encoding,
    /// The opcode map.
    pub map: Map,
    /// The opcode byte.
    pub opcode: u8,
    /// The instruction length.
    pub len: u8,
}

/// The legacy and REX prefixes of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PrefixSet(pub(crate) u16);

impl PrefixSet {
    pub(crate) const LOCK: u16 = 1;
    pub(crate) const REP: u16 = 1 << 1;
    pub(crate) const REPNE: u16 = 1 << 2;
    pub(crate) const OSZ: u16 = 1 << 3;
    pub(crate) const ASZ: u16 = 1 << 4;
    pub(crate) const REX: u16 = 1 << 5;
    pub(crate) const REX_W: u16 = 1 << 6;
    pub(crate) const OSZ_USED: u16 = 1 << 7;
    pub(crate) const ASZ_USED: u16 = 1 << 12;
    pub(crate) const REP_USED: u16 = 1 << 13;

    /// Tells if a `F0` (`lock`) prefix is present.
    #[must_use]
    pub const fn lock(self) -> bool {
        self.0 & Self::LOCK != 0
    }

    /// Tells if the last `F2` or `F3` prefix is `F3` (`rep`).
    #[must_use]
    pub const fn rep(self) -> bool {
        self.0 & Self::REP != 0
    }

    /// Tells if the last `F2` or `F3` prefix is `F2` (`repne`).
    #[must_use]
    pub const fn repne(self) -> bool {
        self.0 & Self::REPNE != 0
    }

    /// Tells if a `66` (operand size) prefix is present.
    #[must_use]
    pub const fn osz(self) -> bool {
        self.0 & Self::OSZ != 0
    }

    /// Tells if a `67` (address size) prefix is present.
    #[must_use]
    pub const fn asz(self) -> bool {
        self.0 & Self::ASZ != 0
    }

    /// Tells if a REX prefix or a REX2 prefix is present.
    #[must_use]
    pub const fn rex(self) -> bool {
        self.0 & Self::REX != 0
    }

    /// Tells if the REX or REX2 `W` bit is set.
    #[must_use]
    pub const fn rex_w(self) -> bool {
        self.0 & Self::REX_W != 0
    }

    /// Gives the number of `66` prefix bytes.
    #[must_use]
    pub const fn count_66(self) -> u8 {
        ((self.0 >> 8) & 0xf) as u8
    }

    /// Tells if the instruction uses its `66` prefix for the operand size or as a
    /// mandatory prefix.
    #[must_use]
    pub const fn osz_used(self) -> bool {
        self.0 & Self::OSZ_USED != 0
    }

    pub(crate) const fn asz_used(self) -> bool {
        self.0 & Self::ASZ_USED != 0
    }

    pub(crate) const fn rep_used(self) -> bool {
        self.0 & Self::REP_USED != 0
    }
}

/// The raw encoding fields of an instruction, for the printer and the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RawFields {
    /// The encoding family.
    pub encoding: Encoding,
    /// The opcode map.
    pub map: Map,
    /// The offset of the opcode byte.
    pub opcode_off: u8,
    /// The opcode byte.
    pub opcode: u8,
    /// The REX byte, or the payload of a REX2 prefix.
    pub rex: Option<u8>,
    /// The `ModRM` byte.
    pub modrm: Option<u8>,
    /// The SIB byte.
    pub sib: Option<u8>,
    /// The offset of the displacement.
    pub disp_off: u8,
    /// The displacement size in bytes, 0, 1, 2, 4 or 8.
    pub disp_size: u8,
    /// The offset of the immediate bytes.
    pub imm_off: u8,
    /// The number of immediate bytes, both immediates included.
    pub imm_size: u8,
}

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
