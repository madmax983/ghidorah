//! The opcode extension groups (Intel SDM, volume 2, table A-6). `ModRM` `reg` selects
//! the row.

#![allow(clippy::enum_glob_use, reason = "the table rows name many mnemonics")]
#![allow(
    clippy::wildcard_imports,
    reason = "the table rows use the spec constants"
)]

use crate::tables::mnem::Mnem::{self, *};
use crate::tables::ops::*;
use crate::tables::{g, s};

const fn alu(a: Spec, b: Spec) -> [Entry; 8] {
    let ops = [Add, Or, Adc, Sbb, And, Sub, Xor];
    let mut out = [UNDEF; 8];
    let mut i = 0;
    while i < 7 {
        out[i] = op2(ops[i], a, b, RW1 | LOCK);
        i += 1;
    }
    out[7] = op2(Cmp, a, b, 0);
    out
}

const fn shift(a: Spec, b: Spec) -> [Entry; 8] {
    let ops: [Mnem; 8] = [Rol, Ror, Rcl, Rcr, Shl, Shr, Shl, Sar];
    let mut out = [UNDEF; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = op2(ops[i], a, b, RW1);
        i += 1;
    }
    out
}

const fn unary(a: Spec, imm: Spec) -> [Entry; 8] {
    [
        op2(Test, a, imm, 0),
        op2(Test, a, imm, 0),
        op1(Not, a, RW1 | LOCK),
        op1(Neg, a, RW1 | LOCK),
        op1(Mul, a, 0),
        op1(Imul, a, 0),
        op1(Div, a, 0),
        op1(Idiv, a, 0),
    ]
}

const fn only(first: Entry, last: Entry) -> [Entry; 8] {
    [first, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, last]
}

/// A packed shift by an immediate.
const fn ps(m: Mnem, reg: Spec) -> Entry {
    op2(m, reg, IB, RW1)
}

/// The rows of a packed shift group: `/2`, `/4` and `/6`.
const fn pshift(r2: Mnem, r4: Mnem, r6: Mnem, reg: Spec) -> [Entry; 8] {
    [
        UNDEF,
        UNDEF,
        ps(r2, reg),
        UNDEF,
        ps(r4, reg),
        UNDEF,
        ps(r6, reg),
        UNDEF,
    ]
}

/// The groups, indexed by the numbers of [`g`].
pub(crate) const GROUPS: [[Entry; 8]; g::COUNT] = [
    alu(EB, IB),
    alu(EV, IZ),
    alu(EV, IBS),
    only(op1(Pop, EV, D64 | W1), UNDEF),
    shift(EB, IB),
    shift(EV, IB),
    shift(EB, ONE),
    shift(EV, ONE),
    shift(EB, CL),
    shift(EV, CL),
    unary(EB, IB),
    unary(EV, IZ),
    [
        op1(Inc, EB, RW1 | LOCK),
        op1(Dec, EB, RW1 | LOCK),
        UNDEF,
        UNDEF,
        UNDEF,
        UNDEF,
        UNDEF,
        UNDEF,
    ],
    [
        op1(Inc, EV, RW1 | LOCK),
        op1(Dec, EV, RW1 | LOCK),
        op1(Call, EV, F64),
        op1(Call, MP, 0),
        op1(Jmp, EV, F64),
        op1(Jmp, MP, 0),
        op1(Push, EV, D64),
        UNDEF,
    ],
    only(op2(Mov, EB, IB, W1), special(s::XABORT)),
    only(op2(Mov, EV, IZ, W1), special(s::XBEGIN)),
    [
        op1(Sldt, EWV, W1),
        op1(Str, EWV, W1),
        op1(Lldt, EWV, 0),
        op1(Ltr, EWV, 0),
        op1(Verr, EWV, 0),
        op1(Verw, EWV, 0),
        UNDEF,
        UNDEF,
    ],
    [
        UNDEF,
        UNDEF,
        UNDEF,
        UNDEF,
        op2(Bt, EV, IB, 0),
        op2(Bts, EV, IB, RW1 | LOCK),
        op2(Btr, EV, IB, RW1 | LOCK),
        op2(Btc, EV, IB, RW1 | LOCK),
    ],
    pshift(Psrlw, Psraw, Psllw, N),
    pshift(Psrlw, Psraw, Psllw, U),
    pshift(Psrld, Psrad, Pslld, N),
    pshift(Psrld, Psrad, Pslld, U),
    [
        UNDEF,
        UNDEF,
        ps(Psrlq, N),
        UNDEF,
        UNDEF,
        UNDEF,
        ps(Psllq, N),
        UNDEF,
    ],
    [
        UNDEF,
        UNDEF,
        ps(Psrlq, U),
        ps(Psrldq, U),
        UNDEF,
        UNDEF,
        ps(Psllq, U),
        ps(Pslldq, U),
    ],
    [
        op1(Prefetch, MB, ADDR),
        op1(Prefetchw, MB, ADDR),
        op1(Prefetchwt1, MB, ADDR),
        op1(Prefetch, MB, ADDR),
        op1(Prefetch, MB, ADDR),
        op1(Prefetch, MB, ADDR),
        op1(Prefetch, MB, ADDR),
        op1(Prefetch, MB, ADDR),
    ],
];
