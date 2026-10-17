//! The status flag effects of each mnemonic (Intel SDM, volume 1, appendix A).
//!
//! `written` holds every flag that the instruction can change, `undefined` included.
//! A mnemonic without a row reads and writes no flag.

use crate::flags::FlagSet;
use crate::tables::mnem::Mnem;

/// The flag effects of one mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlagInfo {
    pub(crate) read: FlagSet,
    pub(crate) written: FlagSet,
    pub(crate) undefined: FlagSet,
}

const NONE: FlagInfo = FlagInfo {
    read: FlagSet::NONE,
    written: FlagSet::NONE,
    undefined: FlagSet::NONE,
};

const CF: u8 = 1;
const PF: u8 = 1 << 1;
const AF: u8 = 1 << 2;
const ZF: u8 = 1 << 3;
const SF: u8 = 1 << 4;
const OF: u8 = 1 << 5;
const DF: u8 = 1 << 6;
const ARITH: u8 = 0x3f;

const fn f(read: u8, written: u8, undefined: u8) -> FlagInfo {
    FlagInfo {
        read: FlagSet::from_bits(read),
        written: FlagSet::from_bits(written | undefined),
        undefined: FlagSet::from_bits(undefined),
    }
}

const ROWS: &[(Mnem, FlagInfo)] = &[
    (Mnem::Add, f(0, ARITH, 0)),
    (Mnem::Sub, f(0, ARITH, 0)),
    (Mnem::Cmp, f(0, ARITH, 0)),
    (Mnem::Neg, f(0, ARITH, 0)),
    (Mnem::Xadd, f(0, ARITH, 0)),
    (Mnem::Cmpxchg, f(0, ARITH, 0)),
    (Mnem::Adc, f(CF, ARITH, 0)),
    (Mnem::Sbb, f(CF, ARITH, 0)),
    (Mnem::Inc, f(0, PF | AF | ZF | SF | OF, 0)),
    (Mnem::Dec, f(0, PF | AF | ZF | SF | OF, 0)),
    (Mnem::And, f(0, CF | PF | ZF | SF | OF, AF)),
    (Mnem::Or, f(0, CF | PF | ZF | SF | OF, AF)),
    (Mnem::Xor, f(0, CF | PF | ZF | SF | OF, AF)),
    (Mnem::Test, f(0, CF | PF | ZF | SF | OF, AF)),
    (Mnem::Shl, f(0, CF | PF | ZF | SF, AF | OF)),
    (Mnem::Shr, f(0, CF | PF | ZF | SF, AF | OF)),
    (Mnem::Sar, f(0, CF | PF | ZF | SF, AF | OF)),
    (Mnem::Shld, f(0, CF | PF | ZF | SF, AF | OF)),
    (Mnem::Shrd, f(0, CF | PF | ZF | SF, AF | OF)),
    (Mnem::Rol, f(0, CF, OF)),
    (Mnem::Ror, f(0, CF, OF)),
    (Mnem::Rcl, f(CF, CF, OF)),
    (Mnem::Rcr, f(CF, CF, OF)),
    (Mnem::Mul, f(0, CF | OF, PF | AF | ZF | SF)),
    (Mnem::Imul, f(0, CF | OF, PF | AF | ZF | SF)),
    (Mnem::Div, f(0, 0, ARITH)),
    (Mnem::Idiv, f(0, 0, ARITH)),
    (Mnem::Bt, f(0, CF, PF | AF | SF | OF)),
    (Mnem::Bts, f(0, CF, PF | AF | SF | OF)),
    (Mnem::Btr, f(0, CF, PF | AF | SF | OF)),
    (Mnem::Btc, f(0, CF, PF | AF | SF | OF)),
    (Mnem::Bsf, f(0, ZF, CF | PF | AF | SF | OF)),
    (Mnem::Bsr, f(0, ZF, CF | PF | AF | SF | OF)),
    (Mnem::Tzcnt, f(0, CF | ZF, PF | AF | SF | OF)),
    (Mnem::Lzcnt, f(0, CF | ZF, PF | AF | SF | OF)),
    (Mnem::Popcnt, f(0, ARITH, 0)),
    (Mnem::Jo, f(OF, 0, 0)),
    (Mnem::Jno, f(OF, 0, 0)),
    (Mnem::Jb, f(CF, 0, 0)),
    (Mnem::Jae, f(CF, 0, 0)),
    (Mnem::Je, f(ZF, 0, 0)),
    (Mnem::Jne, f(ZF, 0, 0)),
    (Mnem::Jbe, f(CF | ZF, 0, 0)),
    (Mnem::Ja, f(CF | ZF, 0, 0)),
    (Mnem::Js, f(SF, 0, 0)),
    (Mnem::Jns, f(SF, 0, 0)),
    (Mnem::Jp, f(PF, 0, 0)),
    (Mnem::Jnp, f(PF, 0, 0)),
    (Mnem::Jl, f(SF | OF, 0, 0)),
    (Mnem::Jge, f(SF | OF, 0, 0)),
    (Mnem::Jle, f(ZF | SF | OF, 0, 0)),
    (Mnem::Jg, f(ZF | SF | OF, 0, 0)),
    (Mnem::Seto, f(OF, 0, 0)),
    (Mnem::Setno, f(OF, 0, 0)),
    (Mnem::Setb, f(CF, 0, 0)),
    (Mnem::Setae, f(CF, 0, 0)),
    (Mnem::Sete, f(ZF, 0, 0)),
    (Mnem::Setne, f(ZF, 0, 0)),
    (Mnem::Setbe, f(CF | ZF, 0, 0)),
    (Mnem::Seta, f(CF | ZF, 0, 0)),
    (Mnem::Sets, f(SF, 0, 0)),
    (Mnem::Setns, f(SF, 0, 0)),
    (Mnem::Setp, f(PF, 0, 0)),
    (Mnem::Setnp, f(PF, 0, 0)),
    (Mnem::Setl, f(SF | OF, 0, 0)),
    (Mnem::Setge, f(SF | OF, 0, 0)),
    (Mnem::Setle, f(ZF | SF | OF, 0, 0)),
    (Mnem::Setg, f(ZF | SF | OF, 0, 0)),
    (Mnem::Cmovo, f(OF, 0, 0)),
    (Mnem::Cmovno, f(OF, 0, 0)),
    (Mnem::Cmovb, f(CF, 0, 0)),
    (Mnem::Cmovae, f(CF, 0, 0)),
    (Mnem::Cmove, f(ZF, 0, 0)),
    (Mnem::Cmovne, f(ZF, 0, 0)),
    (Mnem::Cmovbe, f(CF | ZF, 0, 0)),
    (Mnem::Cmova, f(CF | ZF, 0, 0)),
    (Mnem::Cmovs, f(SF, 0, 0)),
    (Mnem::Cmovns, f(SF, 0, 0)),
    (Mnem::Cmovp, f(PF, 0, 0)),
    (Mnem::Cmovnp, f(PF, 0, 0)),
    (Mnem::Cmovl, f(SF | OF, 0, 0)),
    (Mnem::Cmovge, f(SF | OF, 0, 0)),
    (Mnem::Cmovle, f(ZF | SF | OF, 0, 0)),
    (Mnem::Cmovg, f(ZF | SF | OF, 0, 0)),
    (Mnem::Loope, f(ZF, 0, 0)),
    (Mnem::Loopne, f(ZF, 0, 0)),
    (Mnem::Sahf, f(0, CF | PF | AF | ZF | SF, 0)),
    (Mnem::Lahf, f(CF | PF | AF | ZF | SF, 0, 0)),
    (Mnem::Pushf, f(ARITH | DF, 0, 0)),
    (Mnem::Pushfw, f(ARITH | DF, 0, 0)),
    (Mnem::Popf, f(0, ARITH | DF, 0)),
    (Mnem::Popfw, f(0, ARITH | DF, 0)),
    (Mnem::Iret, f(0, ARITH | DF, 0)),
    (Mnem::Iretw, f(0, ARITH | DF, 0)),
    (Mnem::Iretq, f(0, ARITH | DF, 0)),
    (Mnem::Cmc, f(CF, CF, 0)),
    (Mnem::Clc, f(0, CF, 0)),
    (Mnem::Stc, f(0, CF, 0)),
    (Mnem::Cld, f(0, DF, 0)),
    (Mnem::Std, f(0, DF, 0)),
    (Mnem::Movs, f(DF, 0, 0)),
    (Mnem::Stos, f(DF, 0, 0)),
    (Mnem::Lods, f(DF, 0, 0)),
    (Mnem::Ins, f(DF, 0, 0)),
    (Mnem::Outs, f(DF, 0, 0)),
    (Mnem::Cmps, f(DF | ZF, ARITH, 0)),
    (Mnem::Scas, f(DF | ZF, ARITH, 0)),
    (Mnem::Ucomiss, f(0, ARITH, 0)),
    (Mnem::Ucomisd, f(0, ARITH, 0)),
    (Mnem::Comiss, f(0, ARITH, 0)),
    (Mnem::Comisd, f(0, ARITH, 0)),
    (Mnem::Fcomi, f(0, CF | PF | ZF, 0)),
    (Mnem::Fcomip, f(0, CF | PF | ZF, 0)),
    (Mnem::Fucomi, f(0, CF | PF | ZF, 0)),
    (Mnem::Fucomip, f(0, CF | PF | ZF, 0)),
    (Mnem::Fcmovb, f(CF, 0, 0)),
    (Mnem::Fcmovnb, f(CF, 0, 0)),
    (Mnem::Fcmove, f(ZF, 0, 0)),
    (Mnem::Fcmovne, f(ZF, 0, 0)),
    (Mnem::Fcmovbe, f(CF | ZF, 0, 0)),
    (Mnem::Fcmovnbe, f(CF | ZF, 0, 0)),
    (Mnem::Fcmovu, f(PF, 0, 0)),
    (Mnem::Fcmovnu, f(PF, 0, 0)),
    (Mnem::Lar, f(0, ZF, 0)),
    (Mnem::Lsl, f(0, ZF, 0)),
    (Mnem::Verr, f(0, ZF, 0)),
    (Mnem::Verw, f(0, ZF, 0)),
    (Mnem::Cmpxchg8b, f(0, ZF, 0)),
    (Mnem::Cmpxchg16b, f(0, ZF, 0)),
    (Mnem::Rdrand, f(0, ARITH, 0)),
    (Mnem::Rdseed, f(0, ARITH, 0)),
    (Mnem::Xtest, f(0, ARITH, 0)),
];

const fn build() -> [FlagInfo; Mnem::ALL.len()] {
    let mut table = [NONE; Mnem::ALL.len()];
    let mut i = 0;
    while i < ROWS.len() {
        let (m, info) = ROWS[i];
        table[m as usize] = info;
        i += 1;
    }
    table
}

/// The flag effects indexed by mnemonic.
const TABLE: [FlagInfo; Mnem::ALL.len()] = build();

/// Gives the flag effects of a mnemonic.
pub(crate) fn info(m: Mnem) -> FlagInfo {
    TABLE.get(m as usize).copied().unwrap_or(NONE)
}
