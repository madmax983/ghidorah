//! The operand helpers of the templates: places, reads, writes and addresses.

use ghidorah_ir::{Arg, BuildError, Builder, Cc, FlagOp, Loc, Opc};

use crate::{Insn, Mem, Operand, Reg, RegClass, Seg};

/// The failure of a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fail {
    /// The builder refuses an op.
    Build(BuildError),
    /// An operand has a form that the template does not support. The fit checks of the
    /// templates come first, so this does not occur in a normal run.
    Operand,
}

impl From<BuildError> for Fail {
    fn from(e: BuildError) -> Self {
        Self::Build(e)
    }
}

/// The result of a template step.
pub(super) type Res<T> = Result<T, Fail>;

/// A resolved operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Place {
    /// A general register: the full location, the low bit and the width in bits.
    Gpr {
        /// The full register.
        loc: Loc,
        /// The low bit: 8 for `ah` to `bh`, else 0.
        lo: u8,
        /// The width in bits.
        w: u8,
    },
    /// An XMM register at 128 bits.
    Xmm {
        /// The register.
        loc: Loc,
    },
    /// Memory at an address with a width in bits.
    Mem {
        /// The address.
        addr: Arg,
        /// The access width in bits.
        w: u8,
    },
}

impl Place {
    /// Gives the width of the place in bits.
    pub(super) const fn width(self) -> u8 {
        match self {
            Self::Gpr { w, .. } | Self::Mem { w, .. } => w,
            Self::Xmm { .. } => 128,
        }
    }
}

/// The value mask of a width up to 64 bits.
pub(super) const fn mask(w: u8) -> u64 {
    if w >= 64 { u64::MAX } else { (1 << w) - 1 }
}

/// Gives the width of an operand in bits, or 0 for an operand without a width.
pub(super) fn op_width(op: Operand) -> u8 {
    match op {
        Operand::Reg { reg, .. } => u8::try_from(reg.width_bits()).unwrap_or(0),
        Operand::Mem(m) => u8::try_from(m.width_bytes.saturating_mul(8)).unwrap_or(0),
        Operand::Imm { width, .. } => width.saturating_mul(8),
        Operand::Target { .. } => 64,
        Operand::Opaque => 0,
    }
}

/// Tells if a register has a place: a general register of 8 to 64 bits, or an XMM
/// register when `xmm` is true.
pub(super) fn reg_ok(r: Reg, xmm: bool) -> bool {
    match r.class() {
        RegClass::Gpr => r.number() < 32 && matches!(r.width_bits(), 8 | 16 | 32 | 64),
        RegClass::Xmm => xmm && r.number() < 32,
        _ => false,
    }
}

/// Tells if a memory operand has an address that the lifter computes.
pub(super) fn mem_ok(m: &Mem) -> bool {
    let reg_fits = |r: Option<Reg>| {
        r.is_none_or(|r| {
            r.class() == RegClass::Ip || (r.class() == RegClass::Gpr && r.number() < 32)
        })
    };
    let width = m.access == crate::Access::Address || matches!(m.width_bytes, 1 | 2 | 4 | 8 | 16);
    reg_fits(m.base) && reg_fits(m.index) && width
}

/// Tells if every operand of an instruction has a place, with XMM registers when `xmm` is
/// true.
pub(super) fn operands_ok(insn: &Insn, xmm: bool) -> bool {
    insn.ops().all(|op| match op {
        Operand::Reg { reg, .. } => reg_ok(reg, xmm),
        Operand::Mem(m) => mem_ok(&m) && m.seg.is_none_or(Seg::has_base),
        Operand::Imm { .. } | Operand::Target { .. } => true,
        Operand::Opaque => false,
    })
}

/// The emit context of one instruction.
pub(super) struct Cx<'a> {
    /// The builder.
    pub(super) b: &'a mut Builder,
    /// The instruction.
    pub(super) insn: &'a Insn,
}

impl Cx<'_> {
    /// Adds an op with up to three arguments and gives its value.
    pub(super) fn op(&mut self, opc: Opc, w: u8, sub: u8, a: [Arg; 3]) -> Res<Arg> {
        Ok(Arg::V(self.b.value(opc, w, sub, a)?))
    }

    /// Adds an op with two inputs.
    pub(super) fn bin(&mut self, opc: Opc, w: u8, x: Arg, y: Arg) -> Res<Arg> {
        Ok(Arg::V(self.b.binary(opc, w, x, y)?))
    }

    /// Adds an op with one input.
    pub(super) fn un(&mut self, opc: Opc, w: u8, x: Arg) -> Res<Arg> {
        Ok(Arg::V(self.b.unary(opc, w, x)?))
    }

    /// Reads a location.
    pub(super) fn get(&mut self, loc: Loc) -> Res<Arg> {
        Ok(Arg::V(self.b.get(loc)?))
    }

    /// Writes a location.
    pub(super) fn put(&mut self, loc: Loc, v: Arg) -> Res<()> {
        Ok(self.b.put(loc, v)?)
    }

    /// Changes the width of a value: `ZExt` or `SExt` to a wider width, `Trunc` to a smaller
    /// one, the value itself at the same width.
    pub(super) fn resize(&mut self, x: Arg, from: u8, to: u8, signed: bool) -> Res<Arg> {
        match to.cmp(&from) {
            std::cmp::Ordering::Greater => Ok(Arg::V(self.b.extend(signed, to, from, x)?)),
            std::cmp::Ordering::Less => self.un(Opc::Trunc, to, x),
            std::cmp::Ordering::Equal => Ok(x),
        }
    }

    /// Adds the flag thunk `Flags(op, a, b, c)` and writes it to the flags word.
    pub(super) fn thunk(&mut self, op: FlagOp, w: u8, lhs: Arg, rhs: Arg, old: Arg) -> Res<Arg> {
        let word = Arg::V(self.b.flags(op, w, lhs, rhs, old)?);
        self.put(Loc::Flags, word)?;
        Ok(word)
    }

    /// Reads the flags word.
    pub(super) fn flags(&mut self) -> Res<Arg> {
        self.get(Loc::Flags)
    }

    /// Gives the 1-bit value of an x86 condition on the current flags.
    pub(super) fn cond(&mut self, code: u8) -> Res<Arg> {
        let f = self.flags()?;
        let cc = Cc::x86(code).ok_or(Fail::Operand)?;
        Ok(Arg::V(self.b.cond(cc, f)?))
    }

    /// Gives the address of a memory operand. `seg` adds the `fs` or `gs` base.
    pub(super) fn addr(&mut self, m: &Mem, seg: bool) -> Res<Arg> {
        let mut acc = m.abs_target.map(Arg::k);
        if acc.is_none() {
            if let Some(base) = m.base {
                acc = Some(self.get(Loc::Reg(u16::from(base.number())))?);
            }
            if let Some(index) = m.index {
                let mut scaled = self.get(Loc::Reg(u16::from(index.number())))?;
                if m.scale > 1 {
                    let shift = u64::from(m.scale.trailing_zeros());
                    scaled = self.bin(Opc::Shl, 64, scaled, Arg::k(shift))?;
                }
                acc = Some(match acc {
                    Some(sum) => self.bin(Opc::Add, 64, sum, scaled)?,
                    None => scaled,
                });
            }
            if m.disp != 0 || acc.is_none() {
                let disp = Arg::k(m.disp.cast_unsigned());
                acc = Some(match acc {
                    Some(sum) => self.bin(Opc::Add, 64, sum, disp)?,
                    None => disp,
                });
            }
            if m.addr_width == 32
                && let Some(a) = acc
            {
                acc = Some(self.bin(Opc::And, 64, a, Arg::k(mask(32)))?);
            }
        }
        let mut addr = acc.unwrap_or(Arg::k(0));
        if seg && let Some(s) = m.seg.filter(|s| s.has_base()) {
            let base = if s == Seg::Fs {
                Loc::FS_BASE
            } else {
                Loc::GS_BASE
            };
            let b = self.get(base)?;
            addr = self.bin(Opc::Add, 64, b, addr)?;
        }
        Ok(addr)
    }

    /// Gives the place of a register.
    pub(super) fn reg_place(r: Reg) -> Res<Place> {
        match r.class() {
            RegClass::Gpr if reg_ok(r, false) => Ok(Place::Gpr {
                loc: Loc::Reg(u16::from(r.number())),
                lo: if r.is_high_byte() { 8 } else { 0 },
                w: u8::try_from(r.width_bits()).map_err(|_| Fail::Operand)?,
            }),
            RegClass::Xmm if r.number() < 32 => Ok(Place::Xmm {
                loc: Loc::Reg(32 + u16::from(r.number())),
            }),
            _ => Err(Fail::Operand),
        }
    }

    /// Gives the place of operand `i`. A memory operand gets its address now.
    pub(super) fn place(&mut self, i: usize) -> Res<Place> {
        match self.insn.op(i) {
            Some(Operand::Reg { reg, .. }) => Self::reg_place(reg),
            Some(Operand::Mem(m)) => {
                let addr = self.addr(&m, true)?;
                let w = u8::try_from(m.width_bytes.saturating_mul(8)).map_err(|_| Fail::Operand)?;
                Ok(Place::Mem { addr, w })
            }
            _ => Err(Fail::Operand),
        }
    }

    /// Gives the general register `n` at width `w` as a place.
    pub(super) const fn gpr(n: u16, w: u8) -> Place {
        Place::Gpr {
            loc: Loc::Reg(n),
            lo: 0,
            w,
        }
    }

    /// Reads a place.
    pub(super) fn read(&mut self, p: Place) -> Res<Arg> {
        match p {
            Place::Gpr { loc, lo, w } => {
                let full = self.get(loc)?;
                if w >= 64 {
                    Ok(full)
                } else if lo == 0 {
                    self.un(Opc::Trunc, w, full)
                } else {
                    Ok(Arg::V(self.b.extract(w, full, lo)?))
                }
            }
            Place::Xmm { loc } => self.get(loc),
            Place::Mem { addr, w } => Ok(Arg::V(self.b.load(w, addr)?)),
        }
    }

    /// Gives the full register value after a write of `v` to a register place, without the
    /// write.
    pub(super) fn merged(&mut self, p: Place, v: Arg) -> Res<Arg> {
        match p {
            Place::Gpr { w, .. } if w >= 64 => Ok(v),
            Place::Gpr { w: 32, .. } => self.resize(v, 32, 64, false),
            Place::Gpr { loc, lo, w } => {
                let full = self.get(loc)?;
                Ok(Arg::V(self.b.insert(64, full, v, w, lo)?))
            }
            Place::Xmm { .. } => Ok(v),
            Place::Mem { .. } => Err(Fail::Operand),
        }
    }

    /// Writes a place. A 32-bit register write sets the upper bits to zero. An 8-bit or
    /// 16-bit register write keeps the other bits.
    pub(super) fn write(&mut self, p: Place, v: Arg) -> Res<()> {
        match p {
            Place::Gpr { loc, .. } | Place::Xmm { loc } => {
                let full = self.merged(p, v)?;
                self.put(loc, full)
            }
            Place::Mem { addr, w } => Ok(self.b.store(w, addr, v)?),
        }
    }

    /// Reads operand `i` at width `w`. An immediate gives a constant with its low `w` bits.
    pub(super) fn operand(&mut self, i: usize, w: u8) -> Res<Arg> {
        match self.insn.op(i) {
            Some(Operand::Imm { value, .. }) => Ok(Arg::k(value.cast_unsigned() & mask(w))),
            Some(_) => {
                let p = self.place(i)?;
                self.read(p)
            }
            None => Err(Fail::Operand),
        }
    }

    /// Gives the width of operand `i` in bits, or 0 when it has none.
    pub(super) fn width(&self, i: usize) -> u8 {
        self.insn.op(i).map_or(0, op_width)
    }
}
