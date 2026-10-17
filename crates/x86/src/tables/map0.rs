//! The one-byte opcode map (Intel SDM, volume 2, table A-2).

#![allow(clippy::enum_glob_use, reason = "the table rows name many mnemonics")]
#![allow(
    clippy::wildcard_imports,
    reason = "the table rows use the spec constants"
)]

use crate::tables::mnem::Mnem::{self, *};
use crate::tables::ops::*;
use crate::tables::{g, s};

/// The six rows of one arithmetic or logic operation at `base`.
const fn alu(base: u8, m: Mnem) -> [(u8, Entry); 6] {
    let (acc, lock) = if matches!(m, Cmp) {
        (0, 0)
    } else {
        (RW1, LOCK)
    };
    [
        (base, op2(m, EB, GB, acc | lock)),
        (base + 1, op2(m, EV, GV, acc | lock)),
        (base + 2, op2(m, GB, EB, acc)),
        (base + 3, op2(m, GV, EV, acc)),
        (base + 4, op2(m, AL, IB, acc)),
        (base + 5, op2(m, RAX, IZ, acc)),
    ]
}

/// The eight rows of a register-in-opcode form at `base`.
const fn regs8(base: u8, e: Entry) -> [(u8, Entry); 8] {
    [
        (base, e),
        (base + 1, e),
        (base + 2, e),
        (base + 3, e),
        (base + 4, e),
        (base + 5, e),
        (base + 6, e),
        (base + 7, e),
    ]
}

const JCC: [Mnem; 16] = [
    Jo, Jno, Jb, Jae, Je, Jne, Jbe, Ja, Js, Jns, Jp, Jnp, Jl, Jge, Jle, Jg,
];

const fn jcc8() -> [(u8, Entry); 16] {
    let mut out = [(0, UNDEF); 16];
    let mut i: u8 = 0;
    while i < 16 {
        out[i as usize] = (0x70 + i, op1(JCC[i as usize], JB, 0));
        i += 1;
    }
    out
}

const ROWS: &[(u8, Entry)] = &[
    (0x50, op1(Push, ZV, D64)),
    (0x58, op1(Pop, ZV, D64 | W1)),
    (0x63, op2(Movsxd, GV, ED, W1)),
    (0x68, op1(Push, IZ, D64)),
    (0x69, op3(Imul, GV, EV, IZ, W1)),
    (0x6a, op1(Push, IBS, D64)),
    (0x6b, op3(Imul, GV, EV, IBS, W1)),
    (0x6c, op2(Ins, YB, DX, W1 | REP)),
    (0x6d, op2(Ins, YZ, DX, W1 | REP)),
    (0x6e, op2(Outs, DX, XB, REP)),
    (0x6f, op2(Outs, DX, XZ, REP)),
    (0x80, grp(g::G1_EB)),
    (0x81, grp(g::G1_EV)),
    (0x83, grp(g::G1_EVS)),
    (0x84, op2(Test, EB, GB, 0)),
    (0x85, op2(Test, EV, GV, 0)),
    (0x86, op2(Xchg, EB, GB, RW2 | LOCK)),
    (0x87, op2(Xchg, EV, GV, RW2 | LOCK)),
    (0x88, op2(Mov, EB, GB, W1)),
    (0x89, op2(Mov, EV, GV, W1)),
    (0x8a, op2(Mov, GB, EB, W1)),
    (0x8b, op2(Mov, GV, EV, W1)),
    (0x8c, op2(Mov, EWV, SW, W1)),
    (0x8d, op2(Lea, GV, M0, W1 | ADDR)),
    (0x8e, op2(Mov, SW, EWV, W1)),
    (0x8f, grp(g::G1A)),
    (0x90, special(s::NOP90)),
    (0x98, special(s::CBW)),
    (0x99, special(s::CWD)),
    (0x9b, op0(Fwait, 0)),
    (0x9c, special(s::PUSHF)),
    (0x9d, special(s::POPF)),
    (0x9e, op0(Sahf, 0)),
    (0x9f, op0(Lahf, 0)),
    (0xa0, op2(Movabs, AL, OB, W1)),
    (0xa1, op2(Movabs, RAX, OV, W1)),
    (0xa2, op2(Movabs, OB, AL, W1)),
    (0xa3, op2(Movabs, OV, RAX, W1)),
    (0xa4, op2(Movs, YB, XB, W1 | REP)),
    (0xa5, op2(Movs, YV, XV, W1 | REP)),
    (0xa6, op2(Cmps, XB, YB, REPZ)),
    (0xa7, op2(Cmps, XV, YV, REPZ)),
    (0xa8, op2(Test, AL, IB, 0)),
    (0xa9, op2(Test, RAX, IZ, 0)),
    (0xaa, op2(Stos, YB, AL, W1 | REP)),
    (0xab, op2(Stos, YV, RAX, W1 | REP)),
    (0xac, op2(Lods, AL, XB, W1 | REP)),
    (0xad, op2(Lods, RAX, XV, W1 | REP)),
    (0xae, op2(Scas, AL, YB, REPZ)),
    (0xaf, op2(Scas, RAX, YV, REPZ)),
    (0xc0, grp(g::G2_EB_IB)),
    (0xc1, grp(g::G2_EV_IB)),
    (0xc2, op1(Ret, IW, F64)),
    (0xc3, op0(Ret, F64)),
    (0xc6, grp(g::G11_EB)),
    (0xc7, grp(g::G11_EV)),
    (0xc8, op2(Enter, IW, I2, D64)),
    (0xc9, op0(Leave, D64)),
    (0xca, op1(Retf, IW, 0)),
    (0xcb, op0(Retf, 0)),
    (0xcc, op0(Int3, 0)),
    (0xcd, op1(Int, IB, 0)),
    (0xcf, special(s::IRET)),
    (0xd0, grp(g::G2_EB_1)),
    (0xd1, grp(g::G2_EV_1)),
    (0xd2, grp(g::G2_EB_CL)),
    (0xd3, grp(g::G2_EV_CL)),
    (0xd7, op1(Xlat, XLAT, 0)),
    (0xd8, special(s::X87)),
    (0xd9, special(s::X87)),
    (0xda, special(s::X87)),
    (0xdb, special(s::X87)),
    (0xdc, special(s::X87)),
    (0xdd, special(s::X87)),
    (0xde, special(s::X87)),
    (0xdf, special(s::X87)),
    (0xe0, op1(Loopne, JB, 0)),
    (0xe1, op1(Loope, JB, 0)),
    (0xe2, op1(Loop, JB, 0)),
    (0xe3, special(s::JRCXZ)),
    (0xe4, op2(In, AL, IB, W1)),
    (0xe5, op2(In, EAXZ, IB, W1)),
    (0xe6, op2(Out, IB, AL, 0)),
    (0xe7, op2(Out, IB, EAXZ, 0)),
    (0xe8, op1(Call, JZ, F64)),
    (0xe9, op1(Jmp, JZ, F64)),
    (0xeb, op1(Jmp, JB, F64)),
    (0xec, op2(In, AL, DX, W1)),
    (0xed, op2(In, EAXZ, DX, W1)),
    (0xee, op2(Out, DX, AL, 0)),
    (0xef, op2(Out, DX, EAXZ, 0)),
    (0xf1, op0(Int1, 0)),
    (0xf4, op0(Hlt, 0)),
    (0xf5, op0(Cmc, 0)),
    (0xf6, grp(g::G3_EB)),
    (0xf7, grp(g::G3_EV)),
    (0xf8, op0(Clc, 0)),
    (0xf9, op0(Stc, 0)),
    (0xfa, op0(Cli, 0)),
    (0xfb, op0(Sti, 0)),
    (0xfc, op0(Cld, 0)),
    (0xfd, op0(Std, 0)),
    (0xfe, grp(g::G4)),
    (0xff, grp(g::G5)),
];

const fn build() -> [Entry; 256] {
    let mut t = fill(ROWS);
    let ops = [Add, Or, Adc, Sbb, And, Sub, Xor, Cmp];
    let mut i: u8 = 0;
    while i < 8 {
        let rows = alu(i * 8, ops[i as usize]);
        let mut j = 0;
        while j < 6 {
            t[rows[j].0 as usize] = rows[j].1;
            j += 1;
        }
        i += 1;
    }
    let forms = [
        regs8(0x50, op1(Push, ZV, D64)),
        regs8(0x58, op1(Pop, ZV, D64 | W1)),
        regs8(0x90, op2(Xchg, ZV, RAX, RW2)),
        regs8(0xb0, op2(Mov, ZB, IB, W1)),
        regs8(0xb8, op2(Mov, ZV, IV, W1)),
    ];
    let mut f = 0;
    while f < forms.len() {
        let mut j = 0;
        while j < 8 {
            // Opcode 90 keeps its special row: nop, pause or xchg.
            if forms[f][j].0 != 0x90 {
                t[forms[f][j].0 as usize] = forms[f][j].1;
            }
            j += 1;
        }
        f += 1;
    }
    let jcc = jcc8();
    let mut k = 0;
    while k < 16 {
        t[jcc[k].0 as usize] = jcc[k].1;
        k += 1;
    }
    t
}

/// The rows of the one-byte map.
pub(crate) const MAP0: [Entry; 256] = build();
