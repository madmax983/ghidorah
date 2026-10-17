//! Layer 2: the semantic decoder (design Section 5.1).
//!
//! The decoder looks up the table row of the scanned opcode, resolves groups and special
//! forms, checks the `lock` prefix and builds the operand slots. VEX, EVEX, XOP and the
//! legacy `0F 38`, `0F 3A` and `0F 0F` maps give opaque forms. A REX2 form decodes
//! through the legacy tables for its flow and memory operand, then becomes opaque.

mod operands;
mod special;

use operands::{Ctx, Ext};

use crate::error::{DecodeError, InvalidReason};
use crate::flow::{self, Flow};
use crate::insn::{Encoding, Insn, Map, NO_REG, PrefixSet, Slot, tag};
use crate::len::Layout;
use crate::operand::Access;
use crate::tables::groups::GROUPS;
use crate::tables::map0::MAP0;
use crate::tables::map1::MAP1;
use crate::tables::mnem::Mnem;
use crate::tables::ops::{
    ACCESS, ADDR, D64, Entry, F64, IV, K, Kind, LOCK, MEMF, MOVQ, REGF, RW1, RW2, S, UNDEF, W1,
};

/// Builds the instruction of a scanned layout.
pub(crate) fn build(bytes: &[u8], addr: u64, lay: &Layout) -> Result<Insn, DecodeError> {
    match (lay.enc, lay.map) {
        (Encoding::Legacy, Map::One | Map::M0F) => legacy(bytes, addr, lay),
        (Encoding::Rex2, _) => match legacy(bytes, addr, lay) {
            Ok(full) => Ok(opaque_rex2(&full)),
            // A REX2 form outside the tables is opaque anyway.
            Err(DecodeError::Unsupported { .. }) => Ok(vector(bytes, addr, lay)),
            Err(e) => Err(e),
        },
        _ => Ok(vector(bytes, addr, lay)),
    }
}

/// Gives the prefix bits of a layout. The `used` bits come later.
fn prefix_bits(lay: &Layout) -> PrefixSet {
    let p = lay.pfx;
    let mut bits = u16::from(p.n66.min(15)) << 8;
    let flags = [
        (p.lock, PrefixSet::LOCK),
        (p.rep == 0xf3, PrefixSet::REP),
        (p.rep == 0xf2, PrefixSet::REPNE),
        (p.n66 > 0, PrefixSet::OSZ),
        (p.asz, PrefixSet::ASZ),
        (lay.rex != 0 || lay.enc == Encoding::Rex2, PrefixSet::REX),
        (lay.w(), PrefixSet::REX_W),
    ];
    for (on, bit) in flags {
        if on {
            bits |= bit;
        }
    }
    PrefixSet(bits)
}

/// Makes an instruction with the header fields of a layout and no operands.
fn header(addr: u64, lay: &Layout) -> Insn {
    let seg = lay.pfx.seg.map_or(0, |s| (s as u8) + 1);
    let addr32 = if lay.pfx.asz { 0x20 } else { 0 };
    let has_modrm = if lay.modrm.is_some() { 0x10 } else { 0 };
    let has_sib = if lay.sib.is_some() { 0x20 } else { 0 };
    Insn {
        addr,
        imm: 0,
        disp: 0,
        slots: [Slot::default(); 4],
        base: NO_REG,
        index: NO_REG,
        mnem: Mnem::Vector,
        pfx: prefix_bits(lay),
        len: lay.len,
        n_ops: 0,
        flow: Flow::Seq,
        map: lay.map,
        enc: lay.enc,
        opcode: lay.opcode,
        modrm: lay.modrm.unwrap_or(0),
        sib: lay.sib.unwrap_or(0),
        rex: if lay.enc == Encoding::Rex2 {
            lay.payload[0]
        } else {
            lay.rex
        },
        memfmt: (seg << 2) | addr32,
        imm2: 0,
        disp_at: (lay.disp_off << 4) | (lay.disp_size & 0xf),
        imm_at: (lay.imm_off << 4) | (lay.imm_size & 0xf),
        hdr: (lay.opcode_off & 0xf) | has_modrm | has_sib,
    }
}

/// Looks up the row of a legacy opcode and tells if the mandatory prefix column counts.
fn lookup(lay: &Layout) -> Result<(Entry, bool), DecodeError> {
    let op = usize::from(lay.opcode);
    let col = lay.pfx.column();
    let (mut row, mut col_used) = if lay.map == Map::One {
        (MAP0.get(op).copied().unwrap_or(UNDEF), false)
    } else {
        let cols = MAP1.get(op).copied().unwrap_or([UNDEF; 4]);
        let rm_mem = lay.modrm.is_some_and(|m| m >> 6 != 3);
        match cols.get(usize::from(col)) {
            Some(e) if e.flags & REGF != 0 && rm_mem => (cols[0], false),
            Some(e) if e.flags & MEMF != 0 && !rm_mem => (cols[0], false),
            Some(e) if col != 0 && e.kind != Kind::Undef => (*e, true),
            _ => (cols[0], false),
        }
    };
    if row.kind == Kind::Grp {
        let reg = usize::from(lay.modrm.map_or(0, |m| (m >> 3) & 7));
        row = GROUPS
            .get(usize::from(row.arg))
            .and_then(|g| g.get(reg))
            .copied()
            .unwrap_or(UNDEF);
    }
    if row.kind == Kind::Special {
        // A special form decides itself if it uses the mandatory prefix.
        let r = special::resolve(row.arg, lay)?;
        row = r.e;
        col_used = r.col_used;
    }
    Ok((row, col_used))
}

/// Gives the access of operand `i` of a row. `rm_mem` tells if `ModRM` selects memory.
fn access(row: &Entry, i: usize, kind: K, rm_mem: bool) -> Access {
    let mem_kind = matches!(kind, K::E | K::M | K::W | K::Q);
    if row.flags & ADDR != 0 && mem_kind && rm_mem {
        return Access::Address;
    }
    match (row.flags & ACCESS, i) {
        (W1, 0) => Access::Write,
        (RW1, 0) | (RW2, 0 | 1) => Access::ReadWrite,
        _ => Access::Read,
    }
}

fn invalid(lay: &Layout, reason: InvalidReason) -> DecodeError {
    DecodeError::Invalid {
        len_consumed: lay.len,
        reason,
    }
}

/// Gives the `v` operand size of a row in bytes.
fn operand_size(row: &Entry, lay: &Layout) -> u8 {
    if lay.w() || row.flags & F64 != 0 {
        8
    } else if lay.osz16() {
        2
    } else if row.flags & D64 != 0 {
        8
    } else {
        4
    }
}

/// Which prefixes the operands use, and if the instruction has a target operand.
#[derive(Debug, Clone, Copy, Default)]
struct Usage {
    osz: bool,
    asz: bool,
    direct: bool,
}

/// Builds the operand slots of a row into `insn`.
fn fill(ctx: &Ctx<'_>, row: &Entry, insn: &mut Insn) -> Result<Usage, DecodeError> {
    let mut u = Usage {
        asz: matches!(
            row.mnem,
            Mnem::Jecxz | Mnem::Loop | Mnem::Loope | Mnem::Loopne
        ),
        osz: matches!(
            row.mnem,
            Mnem::Cbw | Mnem::Cwd | Mnem::Pushfw | Mnem::Popfw | Mnem::Iretw
        ),
        direct: false,
    };
    let rm_mem = ctx.rm_is_mem();
    for (i, spec) in row.ops.iter().enumerate() {
        if spec.k == K::None {
            break;
        }
        let slot = ctx.operand(*spec, access(row, i, spec.k, rm_mem), insn)?;
        u.osz |= match spec.k {
            K::J => ctx.first_imm == 2,
            _ if row.flags & F64 != 0 => false,
            _ => matches!(spec.s, S::V | S::Z | S::P) || (spec.s == S::WV && !rm_mem),
        };
        u.asz |= matches!(
            slot.kind(),
            tag::MEM | tag::MOFFS | tag::STR_SRC | tag::STR_DST | tag::XLAT
        );
        u.direct |= slot.kind() == tag::TARGET;
        if let Some(s) = insn.slots.get_mut(i) {
            *s = slot;
        }
        insn.n_ops = insn.n_ops.saturating_add(1);
    }
    Ok(u)
}

/// Adds the `used` bits of the prefixes.
fn used_bits(pfx: PrefixSet, lay: &Layout, col_used: bool, u: Usage) -> PrefixSet {
    let col = lay.pfx.column();
    let mut bits = pfx.0;
    if (col_used && col == 1) || (lay.osz16() && u.osz) {
        bits |= PrefixSet::OSZ_USED;
    }
    if u.asz {
        bits |= PrefixSet::ASZ_USED;
    }
    if col_used && col >= 2 {
        bits |= PrefixSet::REP_USED;
    }
    PrefixSet(bits)
}

/// Decodes a legacy or REX2 instruction through the tables.
fn legacy(bytes: &[u8], addr: u64, lay: &Layout) -> Result<Insn, DecodeError> {
    let (mut row, col_used) = lookup(lay)?;
    match row.kind {
        Kind::Op => {}
        Kind::Opaque => return Ok(vector(bytes, addr, lay)),
        _ => return Err(invalid(lay, InvalidReason::Undefined)),
    }
    let wide = lay.w();
    let rm_mem = lay.modrm.is_some_and(|m| m >> 6 != 3);
    if lay.pfx.lock && (row.flags & LOCK == 0 || !rm_mem) {
        return Err(invalid(lay, InvalidReason::BadLock));
    }
    if wide && row.mnem == Mnem::Mov && row.ops[1] == IV {
        row.mnem = Mnem::Movabs;
    }
    if wide && row.flags & MOVQ != 0 {
        row.mnem = Mnem::Movq;
    }
    let has_i2 = row.ops.iter().any(|s| s.k == K::I2);
    let ctx = Ctx {
        bytes,
        lay,
        osz: operand_size(&row, lay),
        first_imm: lay.imm_size.saturating_sub(u8::from(has_i2)),
        rex_any: lay.rex != 0 || lay.enc == Encoding::Rex2,
        ext: Ext::of_rex(lay),
    };
    let mut insn = header(addr, lay);
    insn.mnem = row.mnem;
    let u = fill(&ctx, &row, &mut insn)?;
    insn.pfx = used_bits(insn.pfx, lay, col_used, u);
    insn.flow = flow::of(row.mnem, u.direct);
    Ok(insn)
}

/// Gives the opaque form of a decoded REX2 instruction: the flow, a memory operand or
/// a branch target stay.
fn opaque_rex2(full: &Insn) -> Insn {
    let mut out = *full;
    out.mnem = Mnem::Vector;
    out.slots = [Slot::default(); 4];
    out.n_ops = 0;
    let keep = full.slots.iter().take(usize::from(full.n_ops)).find(|s| {
        matches!(
            s.kind(),
            tag::MEM | tag::MOFFS | tag::STR_SRC | tag::STR_DST | tag::XLAT | tag::TARGET
        )
    });
    if let Some(s) = keep {
        let mut s = *s;
        if s.kind() != tag::TARGET {
            s.tag = s.kind() | ((Access::ReadWrite as u8) << 4);
            s.size = 0;
        }
        out.slots[0] = s;
        out.n_ops = 1;
    }
    if full.mnem == Mnem::Movabs && full.opcode == 0xa1 && !full.pfx.rex_w() {
        // REX2 with `A1` and W=0 is `jmpabs` with a 64-bit absolute target.
        out.slots[0] = Slot {
            tag: tag::TARGET | tag::ABS,
            size: 8,
            reg: 0,
        };
        out.imm = full.disp;
        out.n_ops = 1;
        out.flow = Flow::Jmp;
    }
    out
}

/// Builds an opaque form: a VEX, EVEX or XOP form, or a legacy `0F 38`, `0F 3A` or
/// `0F 0F` form. A memory operand stays, except for EVEX, whose disp8 scale needs the
/// tables.
fn vector(bytes: &[u8], addr: u64, lay: &Layout) -> Insn {
    let mut insn = header(addr, lay);
    if lay.modrm.is_none_or(|m| m >> 6 == 3) {
        return insn;
    }
    let mut bits = insn.pfx.0 | PrefixSet::ASZ_USED;
    if lay.enc == Encoding::Legacy {
        // The legacy vector maps use the mandatory prefix.
        bits |= PrefixSet::OSZ_USED | PrefixSet::REP_USED;
    }
    insn.pfx = PrefixSet(bits);
    insn.n_ops = 1;
    let access = (Access::ReadWrite as u8) << 4;
    if lay.enc == Encoding::Evex {
        insn.slots[0] = Slot {
            tag: tag::OPAQUE | access,
            size: 0,
            reg: 0,
        };
        return insn;
    }
    let ext = match lay.enc {
        Encoding::Legacy | Encoding::Rex2 => Ext::of_rex(lay),
        _ => Ext::of_vex(lay),
    };
    let ctx = Ctx {
        bytes,
        lay,
        osz: 4,
        first_imm: lay.imm_size,
        rex_any: true,
        ext,
    };
    let vsib = matches!(lay.enc, Encoding::Vex2 | Encoding::Vex3)
        && lay.map == Map::M0F38
        && (0x90..=0x93).contains(&lay.opcode);
    ctx.mem(&mut insn, vsib);
    insn.slots[0] = Slot {
        tag: tag::MEM | access,
        size: 0,
        reg: 0,
    };
    insn
}
