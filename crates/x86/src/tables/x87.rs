//! The x87 opcodes `D8` to `DF` (Intel SDM, volume 2, tables A-7 to A-22).

#![allow(clippy::enum_glob_use, reason = "the table rows name many mnemonics")]

use crate::tables::mnem::Mnem::{self, *};

/// The memory size of an undefined memory form.
pub(crate) const BAD: u8 = 0xff;

/// The memory forms: `(mnemonic, size in bytes)` by opcode and `ModRM` `reg`.
/// Size 0 means a memory operand without a size keyword.
pub(crate) const MEM: [[(Mnem, u8); 8]; 8] = [
    [
        (Fadd, 4),
        (Fmul, 4),
        (Fcom, 4),
        (Fcomp, 4),
        (Fsub, 4),
        (Fsubr, 4),
        (Fdiv, 4),
        (Fdivr, 4),
    ],
    [
        (Fld, 4),
        (Vector, BAD),
        (Fst, 4),
        (Fstp, 4),
        (Fldenv, 0),
        (Fldcw, 2),
        (Fnstenv, 0),
        (Fnstcw, 2),
    ],
    [
        (Fiadd, 4),
        (Fimul, 4),
        (Ficom, 4),
        (Ficomp, 4),
        (Fisub, 4),
        (Fisubr, 4),
        (Fidiv, 4),
        (Fidivr, 4),
    ],
    [
        (Fild, 4),
        (Fisttp, 4),
        (Fist, 4),
        (Fistp, 4),
        (Vector, BAD),
        (Fld, 10),
        (Vector, BAD),
        (Fstp, 10),
    ],
    [
        (Fadd, 8),
        (Fmul, 8),
        (Fcom, 8),
        (Fcomp, 8),
        (Fsub, 8),
        (Fsubr, 8),
        (Fdiv, 8),
        (Fdivr, 8),
    ],
    [
        (Fld, 8),
        (Fisttp, 8),
        (Fst, 8),
        (Fstp, 8),
        (Frstor, 0),
        (Vector, BAD),
        (Fnsave, 0),
        (Fnstsw, 2),
    ],
    [
        (Fiadd, 2),
        (Fimul, 2),
        (Ficom, 2),
        (Ficomp, 2),
        (Fisub, 2),
        (Fisubr, 2),
        (Fidiv, 2),
        (Fidivr, 2),
    ],
    [
        (Fild, 2),
        (Fisttp, 2),
        (Fist, 2),
        (Fistp, 2),
        (Fbld, 10),
        (Fild, 8),
        (Fbstp, 10),
        (Fistp, 8),
    ],
];

/// The operand pattern of a register form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pat {
    /// No instruction.
    Bad,
    /// `st, st(i)`
    St0Sti,
    /// `st(i), st`
    StiSt0,
    /// `st(i)`
    Sti,
    /// One instruction per `ModRM` `rm` value, in [`SINGLES`].
    Single,
}

use Pat::{Bad, Single, St0Sti, Sti, StiSt0};

/// The register forms by opcode and `ModRM` `reg`.
pub(crate) const REG: [[(Mnem, Pat); 8]; 8] = [
    [
        (Fadd, St0Sti),
        (Fmul, St0Sti),
        (Fcom, Sti),
        (Fcomp, Sti),
        (Fsub, St0Sti),
        (Fsubr, St0Sti),
        (Fdiv, St0Sti),
        (Fdivr, St0Sti),
    ],
    [
        (Fld, Sti),
        (Fxch, Sti),
        (Vector, Single),
        (Vector, Bad),
        (Vector, Single),
        (Vector, Single),
        (Vector, Single),
        (Vector, Single),
    ],
    [
        (Fcmovb, St0Sti),
        (Fcmove, St0Sti),
        (Fcmovbe, St0Sti),
        (Fcmovu, St0Sti),
        (Vector, Bad),
        (Vector, Single),
        (Vector, Bad),
        (Vector, Bad),
    ],
    [
        (Fcmovnb, St0Sti),
        (Fcmovne, St0Sti),
        (Fcmovnbe, St0Sti),
        (Fcmovnu, St0Sti),
        (Vector, Single),
        (Fucomi, St0Sti),
        (Fcomi, St0Sti),
        (Vector, Bad),
    ],
    [
        (Fadd, StiSt0),
        (Fmul, StiSt0),
        (Vector, Bad),
        (Vector, Bad),
        (Fsubr, StiSt0),
        (Fsub, StiSt0),
        (Fdivr, StiSt0),
        (Fdiv, StiSt0),
    ],
    [
        (Ffree, Sti),
        (Vector, Bad),
        (Fst, Sti),
        (Fstp, Sti),
        (Fucom, Sti),
        (Fucomp, Sti),
        (Vector, Bad),
        (Vector, Bad),
    ],
    [
        (Faddp, StiSt0),
        (Fmulp, StiSt0),
        (Vector, Bad),
        (Vector, Single),
        (Fsubrp, StiSt0),
        (Fsubp, StiSt0),
        (Fdivrp, StiSt0),
        (Fdivp, StiSt0),
    ],
    [
        (Ffreep, Sti),
        (Vector, Bad),
        (Vector, Bad),
        (Vector, Bad),
        (Vector, Single),
        (Fucomip, St0Sti),
        (Fcomip, St0Sti),
        (Vector, Bad),
    ],
];

/// The forms without a stack register: the opcode, the `ModRM` byte and the mnemonic.
/// `fnstsw ax` is the only one with an operand.
pub(crate) const SINGLES: &[(u8, u8, Mnem)] = &[
    (0xd9, 0xd0, Fnop),
    (0xd9, 0xe0, Fchs),
    (0xd9, 0xe1, Fabs),
    (0xd9, 0xe4, Ftst),
    (0xd9, 0xe5, Fxam),
    (0xd9, 0xe8, Fld1),
    (0xd9, 0xe9, Fldl2t),
    (0xd9, 0xea, Fldl2e),
    (0xd9, 0xeb, Fldpi),
    (0xd9, 0xec, Fldlg2),
    (0xd9, 0xed, Fldln2),
    (0xd9, 0xee, Fldz),
    (0xd9, 0xf0, F2xm1),
    (0xd9, 0xf1, Fyl2x),
    (0xd9, 0xf2, Fptan),
    (0xd9, 0xf3, Fpatan),
    (0xd9, 0xf4, Fxtract),
    (0xd9, 0xf5, Fprem1),
    (0xd9, 0xf6, Fdecstp),
    (0xd9, 0xf7, Fincstp),
    (0xd9, 0xf8, Fprem),
    (0xd9, 0xf9, Fyl2xp1),
    (0xd9, 0xfa, Fsqrt),
    (0xd9, 0xfb, Fsincos),
    (0xd9, 0xfc, Frndint),
    (0xd9, 0xfd, Fscale),
    (0xd9, 0xfe, Fsin),
    (0xd9, 0xff, Fcos),
    (0xda, 0xe9, Fucompp),
    (0xdb, 0xe2, Fnclex),
    (0xdb, 0xe3, Fninit),
    (0xde, 0xd9, Fcompp),
    (0xdf, 0xe0, Fnstsw),
];
