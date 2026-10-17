//! Layer 1: the structural length decoder (design Section 5.1).
//!
//! The scan reads the legacy prefixes and a REX prefix directly before the opcode.
//! Then it reads a REX2, VEX, EVEX or XOP prefix, the opcode and the `ModRM` and SIB bytes.
//! Last it reads the displacement and the immediates. It knows no mnemonics.
//! It never reads more than 15 bytes.

#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::Opts;
use crate::error::{DecodeError, InvalidReason};
use crate::insn::{Encoding, Map};
use crate::regs::Seg;
use crate::tables::attr;

/// The largest instruction length.
const MAX: u8 = 15;

/// The legacy prefixes of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Prefixes {
    /// The `F0` prefix.
    pub(crate) lock: bool,
    /// The last `F2` or `F3` prefix, or 0.
    pub(crate) rep: u8,
    /// The number of `66` prefixes.
    pub(crate) n66: u8,
    /// The `67` prefix.
    pub(crate) asz: bool,
    /// The last segment override.
    pub(crate) seg: Option<Seg>,
}

impl Prefixes {
    /// Gives the mandatory prefix column: 0 none, 1 `66`, 2 `F3`, 3 `F2`.
    ///
    /// The last `F2` or `F3` wins, and both win over `66`.
    pub(crate) const fn column(self) -> u8 {
        match self.rep {
            0xf3 => 2,
            0xf2 => 3,
            _ if self.n66 > 0 => 1,
            _ => 0,
        }
    }
}

/// The structure of one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Layout {
    /// The instruction length.
    pub(crate) len: u8,
    /// The encoding family.
    pub(crate) enc: Encoding,
    /// The opcode map.
    pub(crate) map: Map,
    /// The opcode byte.
    pub(crate) opcode: u8,
    /// The offset of the opcode byte.
    pub(crate) opcode_off: u8,
    /// The `ModRM` byte.
    pub(crate) modrm: Option<u8>,
    /// The SIB byte.
    pub(crate) sib: Option<u8>,
    /// The offset of the displacement.
    pub(crate) disp_off: u8,
    /// The displacement size.
    pub(crate) disp_size: u8,
    /// The offset of the immediates.
    pub(crate) imm_off: u8,
    /// The number of immediate bytes.
    pub(crate) imm_size: u8,
    /// The legacy prefixes.
    pub(crate) pfx: Prefixes,
    /// The REX byte directly before the opcode, or 0.
    pub(crate) rex: u8,
    /// The payload of a REX2, VEX, EVEX or XOP prefix.
    pub(crate) payload: [u8; 3],
}

impl Layout {
    /// Tells if the REX or REX2 prefix has the `W` bit.
    pub(crate) const fn w(&self) -> bool {
        match self.enc {
            Encoding::Rex2 => self.payload[0] & 8 != 0,
            _ => self.rex & 8 != 0,
        }
    }

    /// Tells if the operand size is 16 bits: a `66` prefix without `W`.
    pub(crate) const fn osz16(&self) -> bool {
        self.pfx.n66 > 0 && !self.w()
    }
}

/// A read position in the input.
struct Cur<'a> {
    bytes: &'a [u8],
    pos: u8,
}

fn too_long() -> DecodeError {
    DecodeError::Invalid {
        len_consumed: MAX,
        reason: InvalidReason::TooLong,
    }
}

impl Cur<'_> {
    fn have(&self) -> u8 {
        u8::try_from(self.bytes.len().min(usize::from(MAX))).unwrap_or(MAX)
    }

    fn truncated(&self, need: u8) -> DecodeError {
        DecodeError::Truncated {
            have: self.have(),
            need_at_least: need,
        }
    }

    fn next(&mut self) -> Result<u8, DecodeError> {
        if self.pos >= MAX {
            return Err(too_long());
        }
        let next = self.pos.checked_add(1).ok_or_else(too_long)?;
        let b = self
            .bytes
            .get(usize::from(self.pos))
            .copied()
            .ok_or_else(|| self.truncated(next))?;
        self.pos = next;
        Ok(b)
    }

    fn peek(&self) -> Result<u8, DecodeError> {
        let next = self.pos.checked_add(1).ok_or_else(too_long)?;
        if self.pos >= MAX {
            return Err(too_long());
        }
        self.bytes
            .get(usize::from(self.pos))
            .copied()
            .ok_or_else(|| self.truncated(next))
    }

    /// Checks that the input holds `total` bytes.
    fn need(&self, total: u8) -> Result<(), DecodeError> {
        if total > MAX {
            Err(too_long())
        } else if self.bytes.len() < usize::from(total) {
            Err(self.truncated(total))
        } else {
            Ok(())
        }
    }

    fn invalid(&self, reason: InvalidReason) -> DecodeError {
        DecodeError::Invalid {
            len_consumed: self.pos,
            reason,
        }
    }
}

const fn is_legacy_prefix(b: u8) -> bool {
    matches!(
        b,
        0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3
    )
}

/// Scans the structure of the instruction at the start of `bytes`.
pub(crate) fn scan(bytes: &[u8], opts: Opts) -> Result<Layout, DecodeError> {
    let mut cur = Cur { bytes, pos: 0 };
    let mut pfx = Prefixes::default();
    let mut rex = 0;
    let first = loop {
        let b = cur.next()?;
        match b {
            0xf0 => pfx.lock = true,
            0xf2 | 0xf3 => pfx.rep = b,
            0x66 => pfx.n66 = pfx.n66.saturating_add(1),
            0x67 => pfx.asz = true,
            0x26 => pfx.seg = Some(Seg::Es),
            0x2e => pfx.seg = Some(Seg::Cs),
            0x36 => pfx.seg = Some(Seg::Ss),
            0x3e => pfx.seg = Some(Seg::Ds),
            0x64 => pfx.seg = Some(Seg::Fs),
            0x65 => pfx.seg = Some(Seg::Gs),
            0x40..=0x4f => {
                rex = b;
                continue;
            }
            _ => break b,
        }
        // A REX prefix counts only directly before the opcode.
        rex = 0;
    };
    let mut lay = Layout {
        pfx,
        rex,
        ..Layout::default()
    };
    match first {
        0x0f => {
            let op = cur.next()?;
            let (map, op) = match op {
                0x38 => (Map::M0F38, cur.next()?),
                0x3a => (Map::M0F3A, cur.next()?),
                _ => (Map::M0F, op),
            };
            legacy(&mut cur, lay, map, op, opts)
        }
        0xc4 | 0xc5 | 0x62 => vector(&mut cur, lay, first, opts),
        0x8f if (cur.peek()? & 0x1f) >= 8 => vector(&mut cur, lay, first, opts),
        0xd5 => {
            let p = cur.next()?;
            let map = if p & 0x80 != 0 { Map::M0F } else { Map::One };
            let op = cur.next()?;
            let bad = is_legacy_prefix(op)
                || op & 0xf0 == 0x40
                || (map == Map::One && op == 0x0f)
                || (map == Map::M0F && matches!(op, 0x38 | 0x3a));
            if bad {
                return Err(cur.invalid(InvalidReason::BadRex2));
            }
            lay.enc = Encoding::Rex2;
            lay.rex = 0;
            lay.payload = [p, 0, 0];
            legacy(&mut cur, lay, map, op, opts)
        }
        _ => legacy(&mut cur, lay, Map::One, first, opts),
    }
}

/// Reads the `ModRM` byte, the SIB byte and gives the displacement size.
fn modrm_tail(cur: &mut Cur<'_>, lay: &mut Layout, force_reg: bool) -> Result<(), DecodeError> {
    let m = cur.next()?;
    lay.modrm = Some(m);
    let md = m >> 6;
    let rm = m & 7;
    if md == 3 || force_reg {
        return Ok(());
    }
    lay.disp_size = match md {
        1 => 1,
        2 => 4,
        _ => 0,
    };
    if rm == 4 {
        let s = cur.next()?;
        lay.sib = Some(s);
        if md == 0 && s & 7 == 5 {
            lay.disp_size = 4;
        }
    } else if md == 0 && rm == 5 {
        lay.disp_size = 4;
    }
    Ok(())
}

/// Ends the scan: places the displacement and the immediates and checks the length.
fn finish(cur: &Cur<'_>, mut lay: Layout, imm_size: u8) -> Result<Layout, DecodeError> {
    lay.disp_off = cur.pos;
    lay.imm_off = cur.pos.checked_add(lay.disp_size).ok_or_else(too_long)?;
    lay.imm_size = imm_size;
    let total = lay.imm_off.checked_add(imm_size).ok_or_else(too_long)?;
    cur.need(total)?;
    lay.len = total;
    Ok(lay)
}

/// Gives the size of an immediate kind of the attribute tables.
fn imm_size(kind: u8, lay: &Layout, osz16: bool, opts: Opts) -> u8 {
    let reg = lay.modrm.map_or(0, |m| (m >> 3) & 7);
    let z = if osz16 { 2 } else { 4 };
    let pick = |yes: bool, a: u8, b: u8| if yes { a } else { b };
    match kind {
        attr::I_B | attr::I_JB => 1,
        attr::I_GRP3B => u8::from(reg < 2),
        attr::I_W => 2,
        attr::I_WB => 3,
        attr::I_V if lay.w() => 8,
        attr::I_Z | attr::I_JZ | attr::I_V => z,
        attr::I_JCALL => pick(opts.amd_branch_osz, z, 4),
        attr::I_MOFFS => pick(lay.pfx.asz, 4, 8),
        attr::I_GRP3V => pick(reg < 2, z, 0),
        attr::I_BB => pick(matches!(lay.pfx.column(), 1 | 3), 2, 0),
        _ => 0,
    }
}

/// Scans a legacy or REX2 instruction after its opcode byte.
fn legacy(
    cur: &mut Cur<'_>,
    mut lay: Layout,
    map: Map,
    opcode: u8,
    opts: Opts,
) -> Result<Layout, DecodeError> {
    lay.map = map;
    lay.opcode = opcode;
    lay.opcode_off = cur.pos.checked_sub(1).ok_or_else(too_long)?;
    let a = match map {
        Map::One => attr::of(false, opcode),
        Map::M0F => attr::of(true, opcode),
        Map::M0F38 => attr::MODRM,
        _ => attr::MODRM | attr::I_B,
    };
    if a & attr::UNDEF != 0 {
        return Err(cur.invalid(InvalidReason::Undefined));
    }
    if a & attr::INV64 != 0 {
        return Err(DecodeError::InvalidInMode { len: cur.pos });
    }
    if a & attr::MODRM != 0 {
        // MOV to and from a control or debug register ignores the `mod` field.
        let force_reg = map == Map::M0F && (0x20..=0x23).contains(&opcode);
        modrm_tail(cur, &mut lay, force_reg)?;
    }
    let size = imm_size(a & 0xf, &lay, lay.osz16(), opts);
    finish(cur, lay, size)
}

/// Scans a VEX, EVEX or XOP instruction after its first prefix byte.
fn vector(
    cur: &mut Cur<'_>,
    mut lay: Layout,
    first: u8,
    opts: Opts,
) -> Result<Layout, DecodeError> {
    let p = lay.pfx;
    if opts.strict_vex_legacy_prefix && (p.n66 > 0 || p.rep != 0 || p.lock || lay.rex != 0) {
        return Err(cur.invalid(InvalidReason::VexAfterPrefix));
    }
    lay.rex = 0;
    let p0 = cur.next()?;
    let (enc, map_no) = match first {
        0xc5 => (Encoding::Vex2, 1),
        0xc4 => (Encoding::Vex3, p0 & 0x1f),
        0x62 => (Encoding::Evex, p0 & 7),
        _ => (Encoding::Xop, p0 & 0x1f),
    };
    let valid = match enc {
        Encoding::Vex3 => matches!(map_no, 1..=3 | 5..=7),
        Encoding::Evex => map_no != 0,
        _ => map_no <= 10,
    };
    if !valid {
        return Err(cur.invalid(InvalidReason::BadMap));
    }
    let p1 = if enc == Encoding::Vex2 {
        0
    } else {
        cur.next()?
    };
    let p2 = if enc == Encoding::Evex {
        cur.next()?
    } else {
        0
    };
    lay.enc = enc;
    lay.payload = [p0, p1, p2];
    lay.map = Map::from_number(map_no);
    lay.opcode = cur.next()?;
    lay.opcode_off = cur.pos.checked_sub(1).ok_or_else(too_long)?;
    let op = lay.opcode;
    let vex = matches!(enc, Encoding::Vex2 | Encoding::Vex3);
    if !(vex && lay.map == Map::M0F && op == 0x77) {
        modrm_tail(cur, &mut lay, false)?;
    }
    let size = match lay.map {
        Map::M0F if attr::vex_map1_imm8(op) => 1,
        Map::M0F3A | Map::Xop8 => 1,
        Map::Map7 if matches!(op, 0xf6 | 0xf8) => 4,
        Map::XopA => 4,
        Map::Map4 => {
            // The EVEX `pp` field holds the `66` prefix of the APX legacy forms.
            let osz16 = (p1 & 3) == 1 && (p1 & 0x80) == 0;
            imm_size(attr::evex_map4_imm(op), &lay, osz16, opts)
        }
        _ => 0,
    };
    finish(cur, lay, size)
}
