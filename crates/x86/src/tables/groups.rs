//! The opcode extension groups (Intel SDM, volume 2, table A-6). `ModRM` `reg` selects
//! the row.

#![allow(clippy::enum_glob_use, reason = "the table rows name many mnemonics")]
#![allow(
    clippy::wildcard_imports,
    reason = "the table rows use the spec constants"
)]

use crate::tables::mnem::Mnem::*;
use crate::tables::ops::*;
use crate::tables::{g, s};

/// The arithmetic group: `add` to `cmp` with the operands `a` and `b`.
macro_rules! alu {
    ($a:expr, $b:expr) => {
        [
            op!(Add, $a, $b; RW1 | LOCK),
            op!(Or, $a, $b; RW1 | LOCK),
            op!(Adc, $a, $b; RW1 | LOCK),
            op!(Sbb, $a, $b; RW1 | LOCK),
            op!(And, $a, $b; RW1 | LOCK),
            op!(Sub, $a, $b; RW1 | LOCK),
            op!(Xor, $a, $b; RW1 | LOCK),
            op!(Cmp, $a, $b; 0),
        ]
    };
}

/// The shift group: `rol` to `sar`. `/6` is the `shl` alias.
macro_rules! shift {
    ($a:expr, $b:expr) => {
        [
            op!(Rol, $a, $b; RW1),
            op!(Ror, $a, $b; RW1),
            op!(Rcl, $a, $b; RW1),
            op!(Rcr, $a, $b; RW1),
            op!(Shl, $a, $b; RW1),
            op!(Shr, $a, $b; RW1),
            op!(Shl, $a, $b; RW1),
            op!(Sar, $a, $b; RW1),
        ]
    };
}

/// The unary group: `test` (twice), `not`, `neg`, `mul`, `imul`, `div` and `idiv`.
macro_rules! unary {
    ($a:expr, $imm:expr) => {
        [
            op!(Test, $a, $imm; 0),
            op!(Test, $a, $imm; 0),
            op!(Not, $a; RW1 | LOCK),
            op!(Neg, $a; RW1 | LOCK),
            op!(Mul, $a; 0),
            op!(Imul, $a; 0),
            op!(Div, $a; 0),
            op!(Idiv, $a; 0),
        ]
    };
}

/// A group with rows only at `/0` and `/7`.
macro_rules! only {
    ($first:expr, $last:expr) => {
        [$first, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, UNDEF, $last]
    };
}

/// A packed shift by an immediate.
macro_rules! ps {
    ($m:expr, $reg:expr) => {
        op!($m, $reg, IB; RW1)
    };
}

/// The rows of a packed shift group: `/2`, `/4` and `/6`.
macro_rules! pshift {
    ($r2:expr, $r4:expr, $r6:expr, $reg:expr) => {
        [
            UNDEF,
            UNDEF,
            ps!($r2, $reg),
            UNDEF,
            ps!($r4, $reg),
            UNDEF,
            ps!($r6, $reg),
            UNDEF,
        ]
    };
}

/// The groups, indexed by the numbers of [`g`].
pub(crate) const GROUPS: [[Entry; 8]; g::COUNT] = [
    alu!(EB, IB),
    alu!(EV, IZ),
    alu!(EV, IBS),
    only!(op!(Pop, EV; D64 | W1), UNDEF),
    shift!(EB, IB),
    shift!(EV, IB),
    shift!(EB, ONE),
    shift!(EV, ONE),
    shift!(EB, CL),
    shift!(EV, CL),
    unary!(EB, IB),
    unary!(EV, IZ),
    [
        op!(Inc, EB; RW1 | LOCK),
        op!(Dec, EB; RW1 | LOCK),
        UNDEF,
        UNDEF,
        UNDEF,
        UNDEF,
        UNDEF,
        UNDEF,
    ],
    [
        op!(Inc, EV; RW1 | LOCK),
        op!(Dec, EV; RW1 | LOCK),
        op!(Call, EV; F64),
        op!(Call, MP; 0),
        op!(Jmp, EV; F64),
        op!(Jmp, MP; 0),
        op!(Push, EV; D64),
        UNDEF,
    ],
    only!(op!(Mov, EB, IB; W1), special!(s::XABORT)),
    only!(op!(Mov, EV, IZ; W1), special!(s::XBEGIN)),
    [
        op!(Sldt, EWV; W1),
        op!(Str, EWV; W1),
        op!(Lldt, EWV; 0),
        op!(Ltr, EWV; 0),
        op!(Verr, EWV; 0),
        op!(Verw, EWV; 0),
        UNDEF,
        UNDEF,
    ],
    [
        UNDEF,
        UNDEF,
        UNDEF,
        UNDEF,
        op!(Bt, EV, IB; 0),
        op!(Bts, EV, IB; RW1 | LOCK),
        op!(Btr, EV, IB; RW1 | LOCK),
        op!(Btc, EV, IB; RW1 | LOCK),
    ],
    pshift!(Psrlw, Psraw, Psllw, N),
    pshift!(Psrlw, Psraw, Psllw, U),
    pshift!(Psrld, Psrad, Pslld, N),
    pshift!(Psrld, Psrad, Pslld, U),
    [
        UNDEF,
        UNDEF,
        ps!(Psrlq, N),
        UNDEF,
        UNDEF,
        UNDEF,
        ps!(Psllq, N),
        UNDEF,
    ],
    [
        UNDEF,
        UNDEF,
        ps!(Psrlq, U),
        ps!(Psrldq, U),
        UNDEF,
        UNDEF,
        ps!(Psllq, U),
        ps!(Pslldq, U),
    ],
    [
        op!(Prefetch, MB; ADDR),
        op!(Prefetchw, MB; ADDR),
        op!(Prefetchwt1, MB; ADDR),
        op!(Prefetch, MB; ADDR),
        op!(Prefetch, MB; ADDR),
        op!(Prefetch, MB; ADDR),
        op!(Prefetch, MB; ADDR),
        op!(Prefetch, MB; ADDR),
    ],
];
