//! The row types of the semantic tables, in Intel SDM operand notation.
//!
//! A [`Spec`] pairs an operand kind (`E`, `G`, `I`, `J` and so on) with a size code
//! (`b`, `w`, `d`, `q`, `v`, `z`, `y`). An [`Entry`] holds a mnemonic, four specs and flags.

use crate::tables::mnem::Mnem;

/// An operand kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum K {
    /// No operand.
    None,
    /// `ModRM` `rm`: a general-purpose register or memory.
    E,
    /// `ModRM` `reg`: a general-purpose register.
    G,
    /// `ModRM` `rm`: memory only.
    M,
    /// `ModRM` `rm`: a general-purpose register only.
    R,
    /// The first immediate, zero-extended.
    I,
    /// The first immediate, sign-extended to the operand size.
    Is,
    /// The second immediate byte.
    I2,
    /// A relative branch target.
    J,
    /// A memory offset (`moffs`).
    O,
    /// A general-purpose register in the low 3 bits of the opcode.
    Z,
    /// The accumulator of the size code.
    Acc,
    /// `cl`
    Cl,
    /// `dx`
    Dx,
    /// The constant 1 of the shift forms `D0` to `D1`.
    One,
    /// `ModRM` `reg`: a segment register.
    Sw,
    /// `fs`
    Fs,
    /// `gs`
    Gs,
    /// `ModRM` `reg`: a control register.
    Cr,
    /// `ModRM` `reg`: a debug register.
    Dr,
    /// The string source `ds:[rsi]`.
    X,
    /// The string destination `es:[rdi]`.
    Y,
    /// The `xlat` source `ds:[rbx+al]`.
    Xlat,
    /// `ModRM` `reg`: an XMM register.
    V,
    /// `ModRM` `rm`: an XMM register or memory.
    W,
    /// `ModRM` `rm`: an XMM register only.
    U,
    /// `ModRM` `reg`: an MMX register.
    P,
    /// `ModRM` `rm`: an MMX register or memory.
    Q,
    /// `ModRM` `rm`: an MMX register only.
    N,
    /// `st`, the implicit top of the x87 stack.
    St0,
    /// `ModRM` `rm`: an x87 stack register.
    Sti,
}

/// An operand size code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum S {
    /// No size, or a memory operand without a size keyword.
    U0,
    /// 8 bits.
    B,
    /// 16 bits.
    W,
    /// 32 bits.
    D,
    /// 64 bits.
    Q,
    /// 16, 32 or 64 bits by the operand size.
    V,
    /// 16 bits with `66`, else 32 bits.
    Z,
    /// 64 bits with REX.W, else 32 bits.
    Y,
    /// 128 bits.
    X,
    /// 80 bits.
    T,
    /// A far pointer: 4, 6 or 10 bytes.
    P,
    /// 16 bits in memory, the operand size in a register.
    WV,
    /// 16 bits in memory, 32 bits in a register.
    WD,
}

/// One operand spec of a table row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Spec {
    pub(crate) k: K,
    pub(crate) s: S,
}

/// The entry kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    /// No instruction.
    Undef,
    /// A normal row.
    Op,
    /// A group: `ModRM` `reg` selects the row. The argument is the group number.
    Grp,
    /// A form that needs code. The argument is the special number.
    Special,
    /// An opaque form.
    Opaque,
}

/// A semantic table row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) mnem: Mnem,
    pub(crate) ops: [Spec; 4],
    pub(crate) flags: u16,
    pub(crate) kind: Kind,
    pub(crate) arg: u8,
}

/// Operand 0 is written. Other operands are read.
pub(crate) const W1: u16 = 1;
/// Operand 0 is read and written.
pub(crate) const RW1: u16 = 2;
/// Operands 0 and 1 are read and written.
pub(crate) const RW2: u16 = 3;
/// The mask of the access pattern.
pub(crate) const ACCESS: u16 = 3;
/// The memory operand gives only an address.
pub(crate) const ADDR: u16 = 1 << 2;
/// The `lock` prefix is valid with a memory destination.
pub(crate) const LOCK: u16 = 1 << 3;
/// The operand size is 64 bits by default (`push`, `pop`). `66` gives 16 bits.
pub(crate) const D64: u16 = 1 << 4;
/// The operand size is 64 bits, and `66` does not change it.
pub(crate) const F64: u16 = 1 << 5;
/// REX.W changes the mnemonic to `movq`.
pub(crate) const MOVQ: u16 = 1 << 6;
/// The `F3` prefix is a `rep` prefix of a string instruction.
pub(crate) const REP: u16 = 1 << 7;
/// A string compare: `F3` is `repz` and `F2` is `repnz`.
pub(crate) const REPZ: u16 = 1 << 8;

const fn sp(k: K, s: S) -> Spec {
    Spec { k, s }
}

/// No operand.
pub(crate) const NO: Spec = sp(K::None, S::U0);

pub(crate) const EB: Spec = sp(K::E, S::B);
pub(crate) const EW: Spec = sp(K::E, S::W);
pub(crate) const ED: Spec = sp(K::E, S::D);
pub(crate) const EQ: Spec = sp(K::E, S::Q);
pub(crate) const EV: Spec = sp(K::E, S::V);
pub(crate) const EY: Spec = sp(K::E, S::Y);
pub(crate) const EWV: Spec = sp(K::E, S::WV);
pub(crate) const EWD: Spec = sp(K::E, S::WD);
pub(crate) const GB: Spec = sp(K::G, S::B);
pub(crate) const GD: Spec = sp(K::G, S::D);
pub(crate) const GV: Spec = sp(K::G, S::V);
pub(crate) const GY: Spec = sp(K::G, S::Y);
pub(crate) const GQ: Spec = sp(K::G, S::Q);
pub(crate) const M0: Spec = sp(K::M, S::U0);
pub(crate) const MB: Spec = sp(K::M, S::B);
pub(crate) const MW: Spec = sp(K::M, S::W);
pub(crate) const MD: Spec = sp(K::M, S::D);
pub(crate) const MQ: Spec = sp(K::M, S::Q);
pub(crate) const MY: Spec = sp(K::M, S::Y);
pub(crate) const MX: Spec = sp(K::M, S::X);
pub(crate) const MP: Spec = sp(K::M, S::P);
pub(crate) const RV: Spec = sp(K::R, S::V);
pub(crate) const RQ: Spec = sp(K::R, S::Q);
pub(crate) const RW: Spec = sp(K::R, S::W);
pub(crate) const IB: Spec = sp(K::I, S::B);
pub(crate) const IW: Spec = sp(K::I, S::W);
pub(crate) const IZ: Spec = sp(K::Is, S::Z);
pub(crate) const IV: Spec = sp(K::I, S::V);
pub(crate) const IBS: Spec = sp(K::Is, S::B);
pub(crate) const I2: Spec = sp(K::I2, S::B);
pub(crate) const JB: Spec = sp(K::J, S::B);
pub(crate) const JZ: Spec = sp(K::J, S::Z);
pub(crate) const OB: Spec = sp(K::O, S::B);
pub(crate) const OV: Spec = sp(K::O, S::V);
pub(crate) const ZB: Spec = sp(K::Z, S::B);
pub(crate) const ZV: Spec = sp(K::Z, S::V);
pub(crate) const ZY: Spec = sp(K::Z, S::Y);
pub(crate) const AL: Spec = sp(K::Acc, S::B);
pub(crate) const AX: Spec = sp(K::Acc, S::W);
pub(crate) const RAX: Spec = sp(K::Acc, S::V);
pub(crate) const EAXZ: Spec = sp(K::Acc, S::Z);
pub(crate) const CL: Spec = sp(K::Cl, S::B);
pub(crate) const DX: Spec = sp(K::Dx, S::W);
pub(crate) const ONE: Spec = sp(K::One, S::B);
pub(crate) const SW: Spec = sp(K::Sw, S::W);
pub(crate) const FS: Spec = sp(K::Fs, S::W);
pub(crate) const GS: Spec = sp(K::Gs, S::W);
pub(crate) const CR: Spec = sp(K::Cr, S::Q);
pub(crate) const DR: Spec = sp(K::Dr, S::Q);
pub(crate) const XB: Spec = sp(K::X, S::B);
pub(crate) const XV: Spec = sp(K::X, S::V);
pub(crate) const XZ: Spec = sp(K::X, S::Z);
pub(crate) const YB: Spec = sp(K::Y, S::B);
pub(crate) const YV: Spec = sp(K::Y, S::V);
pub(crate) const YZ: Spec = sp(K::Y, S::Z);
pub(crate) const XLAT: Spec = sp(K::Xlat, S::B);
pub(crate) const V: Spec = sp(K::V, S::X);
pub(crate) const WX: Spec = sp(K::W, S::X);
pub(crate) const WQ: Spec = sp(K::W, S::Q);
pub(crate) const WD: Spec = sp(K::W, S::D);
pub(crate) const U: Spec = sp(K::U, S::X);
pub(crate) const P: Spec = sp(K::P, S::Q);
pub(crate) const QQ: Spec = sp(K::Q, S::Q);
pub(crate) const QD: Spec = sp(K::Q, S::D);
pub(crate) const N: Spec = sp(K::N, S::Q);
pub(crate) const ST0: Spec = sp(K::St0, S::T);
pub(crate) const STI: Spec = sp(K::Sti, S::T);

/// An undefined row.
pub(crate) const UNDEF: Entry = Entry {
    mnem: Mnem::Vector,
    ops: [NO; 4],
    flags: 0,
    kind: Kind::Undef,
    arg: 0,
};

/// A row without operands.
pub(crate) const fn op0(mnem: Mnem, flags: u16) -> Entry {
    op4(mnem, NO, NO, NO, NO, flags)
}

/// A row with one operand.
pub(crate) const fn op1(mnem: Mnem, a: Spec, flags: u16) -> Entry {
    op4(mnem, a, NO, NO, NO, flags)
}

/// A row with two operands.
pub(crate) const fn op2(mnem: Mnem, a: Spec, b: Spec, flags: u16) -> Entry {
    op4(mnem, a, b, NO, NO, flags)
}

/// A row with three operands.
pub(crate) const fn op3(mnem: Mnem, a: Spec, b: Spec, c: Spec, flags: u16) -> Entry {
    op4(mnem, a, b, c, NO, flags)
}

/// A row with four operands.
pub(crate) const fn op4(mnem: Mnem, a: Spec, b: Spec, c: Spec, d: Spec, flags: u16) -> Entry {
    Entry {
        mnem,
        ops: [a, b, c, d],
        flags,
        kind: Kind::Op,
        arg: 0,
    }
}

/// A group row: `ModRM` `reg` selects the row of group `id`.
pub(crate) const fn grp(id: u8) -> Entry {
    Entry {
        kind: Kind::Grp,
        arg: id,
        ..UNDEF
    }
}

/// A row that needs code: special form `id`.
pub(crate) const fn special(id: u8) -> Entry {
    Entry {
        kind: Kind::Special,
        arg: id,
        ..UNDEF
    }
}

/// An opaque row.
pub(crate) const OPAQUE: Entry = Entry {
    kind: Kind::Opaque,
    ..UNDEF
};

/// Fills a table of 256 rows from sparse `(opcode, row)` pairs.
pub(crate) const fn fill(rows: &[(u8, Entry)]) -> [Entry; 256] {
    let mut table = [UNDEF; 256];
    let mut i = 0;
    while i < rows.len() {
        let (op, e) = rows[i];
        table[op as usize] = e;
        i += 1;
    }
    table
}
