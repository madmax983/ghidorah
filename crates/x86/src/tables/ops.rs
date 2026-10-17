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

/// The instruction writes operand 0 and reads the other operands.
pub(crate) const W1: u16 = 1;
/// The instruction reads and writes operand 0.
pub(crate) const RW1: u16 = 2;
/// The instruction reads and writes operands 0 and 1.
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

/// No operand.
pub(crate) const NO: Spec = Spec {
    k: K::None,
    s: S::U0,
};

pub(crate) const EB: Spec = Spec { k: K::E, s: S::B };
pub(crate) const EW: Spec = Spec { k: K::E, s: S::W };
pub(crate) const ED: Spec = Spec { k: K::E, s: S::D };
pub(crate) const EQ: Spec = Spec { k: K::E, s: S::Q };
pub(crate) const EV: Spec = Spec { k: K::E, s: S::V };
pub(crate) const EY: Spec = Spec { k: K::E, s: S::Y };
pub(crate) const EWV: Spec = Spec { k: K::E, s: S::WV };
pub(crate) const EWD: Spec = Spec { k: K::E, s: S::WD };
pub(crate) const GB: Spec = Spec { k: K::G, s: S::B };
pub(crate) const GD: Spec = Spec { k: K::G, s: S::D };
pub(crate) const GV: Spec = Spec { k: K::G, s: S::V };
pub(crate) const GY: Spec = Spec { k: K::G, s: S::Y };
pub(crate) const GQ: Spec = Spec { k: K::G, s: S::Q };
pub(crate) const M0: Spec = Spec { k: K::M, s: S::U0 };
pub(crate) const MB: Spec = Spec { k: K::M, s: S::B };
pub(crate) const MW: Spec = Spec { k: K::M, s: S::W };
pub(crate) const MD: Spec = Spec { k: K::M, s: S::D };
pub(crate) const MQ: Spec = Spec { k: K::M, s: S::Q };
pub(crate) const MY: Spec = Spec { k: K::M, s: S::Y };
pub(crate) const MX: Spec = Spec { k: K::M, s: S::X };
pub(crate) const MP: Spec = Spec { k: K::M, s: S::P };
pub(crate) const RV: Spec = Spec { k: K::R, s: S::V };
pub(crate) const RQ: Spec = Spec { k: K::R, s: S::Q };
pub(crate) const RW: Spec = Spec { k: K::R, s: S::W };
pub(crate) const IB: Spec = Spec { k: K::I, s: S::B };
pub(crate) const IW: Spec = Spec { k: K::I, s: S::W };
pub(crate) const IZ: Spec = Spec { k: K::Is, s: S::Z };
pub(crate) const IV: Spec = Spec { k: K::I, s: S::V };
pub(crate) const IBS: Spec = Spec { k: K::Is, s: S::B };
pub(crate) const I2: Spec = Spec { k: K::I2, s: S::B };
pub(crate) const JB: Spec = Spec { k: K::J, s: S::B };
pub(crate) const JZ: Spec = Spec { k: K::J, s: S::Z };
pub(crate) const OB: Spec = Spec { k: K::O, s: S::B };
pub(crate) const OV: Spec = Spec { k: K::O, s: S::V };
pub(crate) const ZB: Spec = Spec { k: K::Z, s: S::B };
pub(crate) const ZV: Spec = Spec { k: K::Z, s: S::V };
pub(crate) const ZY: Spec = Spec { k: K::Z, s: S::Y };
pub(crate) const AL: Spec = Spec { k: K::Acc, s: S::B };
pub(crate) const AX: Spec = Spec { k: K::Acc, s: S::W };
pub(crate) const RAX: Spec = Spec { k: K::Acc, s: S::V };
pub(crate) const EAXZ: Spec = Spec { k: K::Acc, s: S::Z };
pub(crate) const CL: Spec = Spec { k: K::Cl, s: S::B };
pub(crate) const DX: Spec = Spec { k: K::Dx, s: S::W };
pub(crate) const ONE: Spec = Spec { k: K::One, s: S::B };
pub(crate) const SW: Spec = Spec { k: K::Sw, s: S::W };
pub(crate) const FS: Spec = Spec { k: K::Fs, s: S::W };
pub(crate) const GS: Spec = Spec { k: K::Gs, s: S::W };
pub(crate) const CR: Spec = Spec { k: K::Cr, s: S::Q };
pub(crate) const DR: Spec = Spec { k: K::Dr, s: S::Q };
pub(crate) const XB: Spec = Spec { k: K::X, s: S::B };
pub(crate) const XV: Spec = Spec { k: K::X, s: S::V };
pub(crate) const XZ: Spec = Spec { k: K::X, s: S::Z };
pub(crate) const YB: Spec = Spec { k: K::Y, s: S::B };
pub(crate) const YV: Spec = Spec { k: K::Y, s: S::V };
pub(crate) const YZ: Spec = Spec { k: K::Y, s: S::Z };
pub(crate) const XLAT: Spec = Spec {
    k: K::Xlat,
    s: S::B,
};
pub(crate) const V: Spec = Spec { k: K::V, s: S::X };
pub(crate) const WX: Spec = Spec { k: K::W, s: S::X };
pub(crate) const WQ: Spec = Spec { k: K::W, s: S::Q };
pub(crate) const WD: Spec = Spec { k: K::W, s: S::D };
pub(crate) const U: Spec = Spec { k: K::U, s: S::X };
pub(crate) const P: Spec = Spec { k: K::P, s: S::Q };
pub(crate) const QQ: Spec = Spec { k: K::Q, s: S::Q };
pub(crate) const QD: Spec = Spec { k: K::Q, s: S::D };
pub(crate) const N: Spec = Spec { k: K::N, s: S::Q };
pub(crate) const ST0: Spec = Spec { k: K::St0, s: S::T };
pub(crate) const STI: Spec = Spec { k: K::Sti, s: S::T };

/// An undefined row.
pub(crate) const UNDEF: Entry = Entry {
    mnem: Mnem::Vector,
    ops: [NO; 4],
    flags: 0,
    kind: Kind::Undef,
    arg: 0,
};

/// Makes a normal row: a mnemonic, up to four operand specs, then `;` and the flags.
///
/// The tables use macros, not `const fn` constructors. So the tables hold no function
/// that runs only at compile time.
macro_rules! op {
    (@ $m:expr, [$a:expr, $b:expr, $c:expr, $d:expr], $f:expr) => {
        $crate::tables::ops::Entry {
            mnem: $m,
            ops: [$a, $b, $c, $d],
            flags: $f,
            kind: $crate::tables::ops::Kind::Op,
            arg: 0,
        }
    };
    ($m:expr; $f:expr) => {
        $crate::tables::ops::op!(@ $m, [
            $crate::tables::ops::NO,
            $crate::tables::ops::NO,
            $crate::tables::ops::NO,
            $crate::tables::ops::NO
        ], $f)
    };
    ($m:expr, $a:expr; $f:expr) => {
        $crate::tables::ops::op!(@ $m, [
            $a,
            $crate::tables::ops::NO,
            $crate::tables::ops::NO,
            $crate::tables::ops::NO
        ], $f)
    };
    ($m:expr, $a:expr, $b:expr; $f:expr) => {
        $crate::tables::ops::op!(@ $m, [
            $a,
            $b,
            $crate::tables::ops::NO,
            $crate::tables::ops::NO
        ], $f)
    };
    ($m:expr, $a:expr, $b:expr, $c:expr; $f:expr) => {
        $crate::tables::ops::op!(@ $m, [$a, $b, $c, $crate::tables::ops::NO], $f)
    };
    ($m:expr, $a:expr, $b:expr, $c:expr, $d:expr; $f:expr) => {
        $crate::tables::ops::op!(@ $m, [$a, $b, $c, $d], $f)
    };
}
pub(crate) use op;

/// Makes a group row: `ModRM` `reg` selects the row of group `id`.
macro_rules! grp {
    ($id:expr) => {
        $crate::tables::ops::Entry {
            kind: $crate::tables::ops::Kind::Grp,
            arg: $id,
            ..$crate::tables::ops::UNDEF
        }
    };
}
pub(crate) use grp;

/// Makes a row that needs code: special form `id`.
macro_rules! special {
    ($id:expr) => {
        $crate::tables::ops::Entry {
            kind: $crate::tables::ops::Kind::Special,
            arg: $id,
            ..$crate::tables::ops::UNDEF
        }
    };
}
pub(crate) use special;

/// An opaque row.
pub(crate) const OPAQUE: Entry = Entry {
    kind: Kind::Opaque,
    ..UNDEF
};

/// Fills a table of 256 rows from sparse `(opcode, row)` pairs.
macro_rules! fill {
    ($rows:expr) => {{
        let rows: &[(u8, $crate::tables::ops::Entry)] = $rows;
        let mut table = [$crate::tables::ops::UNDEF; 256];
        let mut i = 0;
        while i < rows.len() {
            table[rows[i].0 as usize] = rows[i].1;
            i += 1;
        }
        table
    }};
}
pub(crate) use fill;
