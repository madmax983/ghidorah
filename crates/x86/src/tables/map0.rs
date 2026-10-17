//! The one-byte opcode map (Intel SDM, volume 2, table A-2).

#![allow(clippy::enum_glob_use, reason = "the table rows name many mnemonics")]
#![allow(
    clippy::wildcard_imports,
    reason = "the table rows use the spec constants"
)]

use crate::tables::mnem::Mnem::{self, *};
use crate::tables::ops::*;
use crate::tables::{g, s};

/// The condition codes in opcode order.
const JCC: [Mnem; 16] = [
    Jo, Jno, Jb, Jae, Je, Jne, Jbe, Ja, Js, Jns, Jp, Jnp, Jl, Jge, Jle, Jg,
];

/// The arithmetic and logic operations in opcode order.
const ALU: [Mnem; 8] = [Add, Or, Adc, Sbb, And, Sub, Xor, Cmp];

/// The register-in-opcode forms: the first opcode and the row of all eight opcodes.
const REG8: [(u8, Entry); 5] = [
    (0x50, op!(Push, ZV; D64)),
    (0x58, op!(Pop, ZV; D64 | W1)),
    (0x90, op!(Xchg, ZV, RAX; RW2)),
    (0xb0, op!(Mov, ZB, IB; W1)),
    (0xb8, op!(Mov, ZV, IV; W1)),
];

const ROWS: &[(u8, Entry)] = &[
    (0x63, op!(Movsxd, GV, ED; W1)),
    (0x68, op!(Push, IZ; D64)),
    (0x69, op!(Imul, GV, EV, IZ; W1)),
    (0x6a, op!(Push, IBS; D64)),
    (0x6b, op!(Imul, GV, EV, IBS; W1)),
    (0x6c, op!(Ins, YB, DX; W1 | REP)),
    (0x6d, op!(Ins, YZ, DX; W1 | REP)),
    (0x6e, op!(Outs, DX, XB; REP)),
    (0x6f, op!(Outs, DX, XZ; REP)),
    (0x80, grp!(g::G1_EB)),
    (0x81, grp!(g::G1_EV)),
    (0x83, grp!(g::G1_EVS)),
    (0x84, op!(Test, EB, GB; 0)),
    (0x85, op!(Test, EV, GV; 0)),
    (0x86, op!(Xchg, EB, GB; RW2 | LOCK)),
    (0x87, op!(Xchg, EV, GV; RW2 | LOCK)),
    (0x88, op!(Mov, EB, GB; W1)),
    (0x89, op!(Mov, EV, GV; W1)),
    (0x8a, op!(Mov, GB, EB; W1)),
    (0x8b, op!(Mov, GV, EV; W1)),
    (0x8c, op!(Mov, EWV, SW; W1)),
    (0x8d, op!(Lea, GV, M0; W1 | ADDR)),
    (0x8e, op!(Mov, SW, EWV; W1)),
    (0x8f, grp!(g::G1A)),
    (0x90, special!(s::NOP90)),
    (0x98, special!(s::CBW)),
    (0x99, special!(s::CWD)),
    (0x9b, op!(Fwait; 0)),
    (0x9c, special!(s::PUSHF)),
    (0x9d, special!(s::POPF)),
    (0x9e, op!(Sahf; 0)),
    (0x9f, op!(Lahf; 0)),
    (0xa0, op!(Movabs, AL, OB; W1)),
    (0xa1, op!(Movabs, RAX, OV; W1)),
    (0xa2, op!(Movabs, OB, AL; W1)),
    (0xa3, op!(Movabs, OV, RAX; W1)),
    (0xa4, op!(Movs, YB, XB; W1 | REP)),
    (0xa5, op!(Movs, YV, XV; W1 | REP)),
    (0xa6, op!(Cmps, XB, YB; REPZ)),
    (0xa7, op!(Cmps, XV, YV; REPZ)),
    (0xa8, op!(Test, AL, IB; 0)),
    (0xa9, op!(Test, RAX, IZ; 0)),
    (0xaa, op!(Stos, YB, AL; W1 | REP)),
    (0xab, op!(Stos, YV, RAX; W1 | REP)),
    (0xac, op!(Lods, AL, XB; W1 | REP)),
    (0xad, op!(Lods, RAX, XV; W1 | REP)),
    (0xae, op!(Scas, AL, YB; REPZ)),
    (0xaf, op!(Scas, RAX, YV; REPZ)),
    (0xc0, grp!(g::G2_EB_IB)),
    (0xc1, grp!(g::G2_EV_IB)),
    (0xc2, op!(Ret, IW; F64)),
    (0xc3, op!(Ret; F64)),
    (0xc6, grp!(g::G11_EB)),
    (0xc7, grp!(g::G11_EV)),
    (0xc8, op!(Enter, IW, I2; D64)),
    (0xc9, op!(Leave; D64)),
    (0xca, op!(Retf, IW; 0)),
    (0xcb, op!(Retf; 0)),
    (0xcc, op!(Int3; 0)),
    (0xcd, op!(Int, IB; 0)),
    (0xcf, special!(s::IRET)),
    (0xd0, grp!(g::G2_EB_1)),
    (0xd1, grp!(g::G2_EV_1)),
    (0xd2, grp!(g::G2_EB_CL)),
    (0xd3, grp!(g::G2_EV_CL)),
    (0xd7, op!(Xlat, XLAT; 0)),
    (0xd8, special!(s::X87)),
    (0xd9, special!(s::X87)),
    (0xda, special!(s::X87)),
    (0xdb, special!(s::X87)),
    (0xdc, special!(s::X87)),
    (0xdd, special!(s::X87)),
    (0xde, special!(s::X87)),
    (0xdf, special!(s::X87)),
    (0xe0, op!(Loopne, JB; 0)),
    (0xe1, op!(Loope, JB; 0)),
    (0xe2, op!(Loop, JB; 0)),
    (0xe3, special!(s::JRCXZ)),
    (0xe4, op!(In, AL, IB; W1)),
    (0xe5, op!(In, EAXZ, IB; W1)),
    (0xe6, op!(Out, IB, AL; 0)),
    (0xe7, op!(Out, IB, EAXZ; 0)),
    (0xe8, op!(Call, JZ; F64)),
    (0xe9, op!(Jmp, JZ; F64)),
    (0xeb, op!(Jmp, JB; F64)),
    (0xec, op!(In, AL, DX; W1)),
    (0xed, op!(In, EAXZ, DX; W1)),
    (0xee, op!(Out, DX, AL; 0)),
    (0xef, op!(Out, DX, EAXZ; 0)),
    (0xf1, op!(Int1; 0)),
    (0xf4, op!(Hlt; 0)),
    (0xf5, op!(Cmc; 0)),
    (0xf6, grp!(g::G3_EB)),
    (0xf7, grp!(g::G3_EV)),
    (0xf8, op!(Clc; 0)),
    (0xf9, op!(Stc; 0)),
    (0xfa, op!(Cli; 0)),
    (0xfb, op!(Sti; 0)),
    (0xfc, op!(Cld; 0)),
    (0xfd, op!(Std; 0)),
    (0xfe, grp!(g::G4)),
    (0xff, grp!(g::G5)),
];

/// The rows of the one-byte map.
pub(crate) const MAP0: [Entry; 256] = {
    let mut t = fill!(ROWS);
    let mut i = 0;
    while i < 8 {
        let m = ALU[i];
        let (acc, lock) = if matches!(m, Cmp) {
            (0, 0)
        } else {
            (RW1, LOCK)
        };
        let base = i * 8;
        t[base] = op!(m, EB, GB; acc | lock);
        t[base + 1] = op!(m, EV, GV; acc | lock);
        t[base + 2] = op!(m, GB, EB; acc);
        t[base + 3] = op!(m, GV, EV; acc);
        t[base + 4] = op!(m, AL, IB; acc);
        t[base + 5] = op!(m, RAX, IZ; acc);
        i += 1;
    }
    let mut f = 0;
    while f < REG8.len() {
        let (first, e) = REG8[f];
        let mut j = 0;
        while j < 8 {
            let op = first as usize + j;
            // Opcode 90 keeps its special row: nop, pause or xchg.
            if op != 0x90 {
                t[op] = e;
            }
            j += 1;
        }
        f += 1;
    }
    let mut k = 0;
    while k < 16 {
        t[0x70 + k] = op!(JCC[k], JB; 0);
        k += 1;
    }
    t
};
