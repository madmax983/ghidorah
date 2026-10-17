//! The `0F` opcode map (Intel SDM, volume 2, tables A-3 and A-4).
//!
//! Each opcode has four columns: no prefix, `66`, `F3` and `F2`. The decoder uses the
//! column of the mandatory prefix. A missing column falls back to the first column.

#![allow(clippy::enum_glob_use, reason = "the table rows name many mnemonics")]
#![allow(
    clippy::wildcard_imports,
    reason = "the table rows use the spec constants"
)]

use crate::tables::mnem::Mnem::{self, *};
use crate::tables::ops::*;
use crate::tables::{g, s};

/// A row: opcode, column (0 none, 1 `66`, 2 `F3`, 3 `F2`) and entry.
type Row = (u8, u8, Entry);

const ROWS: &[Row] = &[
    (0x00, 0, grp!(g::G6)),
    (0x01, 0, special!(s::G7)),
    (0x02, 0, op!(Lar, GV, EWV; W1)),
    (0x03, 0, op!(Lsl, GV, EWV; W1)),
    (0x05, 0, op!(Syscall; 0)),
    (0x06, 0, op!(Clts; 0)),
    (0x07, 0, op!(Sysret; 0)),
    (0x08, 0, op!(Invd; 0)),
    (0x09, 0, op!(Wbinvd; 0)),
    (0x0b, 0, op!(Ud2; 0)),
    (0x0d, 0, grp!(g::G0D)),
    (0x0e, 0, op!(Femms; 0)),
    (0x0f, 0, OPAQUE),
    (0x10, 0, op!(Movups, V, WX; W1)),
    (0x10, 1, op!(Movupd, V, WX; W1)),
    (0x10, 2, op!(Movss, V, WD; W1)),
    (0x10, 3, op!(Movsd, V, WQ; W1)),
    (0x11, 0, op!(Movups, WX, V; W1)),
    (0x11, 1, op!(Movupd, WX, V; W1)),
    (0x11, 2, op!(Movss, WD, V; W1)),
    (0x11, 3, op!(Movsd, WQ, V; W1)),
    (0x12, 0, special!(s::MOVLPS12)),
    (0x12, 1, op!(Movlpd, V, MQ; RW1)),
    (0x12, 2, op!(Movsldup, V, WX; W1)),
    (0x12, 3, op!(Movddup, V, WQ; W1)),
    (0x13, 0, op!(Movlps, MQ, V; W1)),
    (0x13, 1, op!(Movlpd, MQ, V; W1)),
    (0x14, 0, op!(Unpcklps, V, WX; RW1)),
    (0x14, 1, op!(Unpcklpd, V, WX; RW1)),
    (0x15, 0, op!(Unpckhps, V, WX; RW1)),
    (0x15, 1, op!(Unpckhpd, V, WX; RW1)),
    (0x16, 0, special!(s::MOVHPS16)),
    (0x16, 1, op!(Movhpd, V, MQ; RW1)),
    (0x16, 2, op!(Movshdup, V, WX; W1)),
    (0x17, 0, op!(Movhps, MQ, V; W1)),
    (0x17, 1, op!(Movhpd, MQ, V; W1)),
    (0x18, 0, special!(s::HINT18)),
    (0x19, 0, op!(Nop, EV; ADDR)),
    (0x1a, 0, op!(Nop, EV; ADDR)),
    (0x1b, 0, op!(Nop, EV; ADDR)),
    (0x1c, 0, special!(s::HINT1C)),
    (0x1d, 0, op!(Nop, EV; ADDR)),
    (0x1e, 0, op!(Nop, EV; ADDR)),
    (0x1e, 2, special!(s::HINT1E)),
    (0x1f, 0, op!(Nop, EV; ADDR)),
    (0x20, 0, op!(Mov, RQ, CR; W1)),
    (0x21, 0, op!(Mov, RQ, DR; W1)),
    (0x22, 0, op!(Mov, CR, RQ; W1)),
    (0x23, 0, op!(Mov, DR, RQ; W1)),
    (0x28, 0, op!(Movaps, V, WX; W1)),
    (0x28, 1, op!(Movapd, V, WX; W1)),
    (0x29, 0, op!(Movaps, WX, V; W1)),
    (0x29, 1, op!(Movapd, WX, V; W1)),
    (0x2a, 0, op!(Cvtpi2ps, V, QQ; RW1)),
    (0x2a, 1, op!(Cvtpi2pd, V, QQ; W1)),
    (0x2a, 2, op!(Cvtsi2ss, V, EY; RW1)),
    (0x2a, 3, op!(Cvtsi2sd, V, EY; RW1)),
    (0x2b, 0, op!(Movntps, MX, V; W1)),
    (0x2b, 1, op!(Movntpd, MX, V; W1)),
    (0x2c, 0, op!(Cvttps2pi, P, WQ; W1)),
    (0x2c, 1, op!(Cvttpd2pi, P, WX; W1)),
    (0x2c, 2, op!(Cvttss2si, GY, WD; W1)),
    (0x2c, 3, op!(Cvttsd2si, GY, WQ; W1)),
    (0x2d, 0, op!(Cvtps2pi, P, WQ; W1)),
    (0x2d, 1, op!(Cvtpd2pi, P, WX; W1)),
    (0x2d, 2, op!(Cvtss2si, GY, WD; W1)),
    (0x2d, 3, op!(Cvtsd2si, GY, WQ; W1)),
    (0x2e, 0, op!(Ucomiss, V, WD; 0)),
    (0x2e, 1, op!(Ucomisd, V, WQ; 0)),
    (0x2f, 0, op!(Comiss, V, WD; 0)),
    (0x2f, 1, op!(Comisd, V, WQ; 0)),
    (0x30, 0, op!(Wrmsr; 0)),
    (0x31, 0, op!(Rdtsc; 0)),
    (0x32, 0, op!(Rdmsr; 0)),
    (0x33, 0, op!(Rdpmc; 0)),
    (0x34, 0, op!(Sysenter; 0)),
    (0x35, 0, op!(Sysexit; 0)),
    (0x37, 0, special!(s::UNSUP)),
    (0x50, 0, op!(Movmskps, GD, U; W1)),
    (0x50, 1, op!(Movmskpd, GD, U; W1)),
    (0x51, 0, op!(Sqrtps, V, WX; W1)),
    (0x51, 1, op!(Sqrtpd, V, WX; W1)),
    (0x51, 2, op!(Sqrtss, V, WD; RW1)),
    (0x51, 3, op!(Sqrtsd, V, WQ; RW1)),
    (0x52, 0, op!(Rsqrtps, V, WX; W1)),
    (0x52, 2, op!(Rsqrtss, V, WD; RW1)),
    (0x53, 0, op!(Rcpps, V, WX; W1)),
    (0x53, 2, op!(Rcpss, V, WD; RW1)),
    (0x54, 0, op!(Andps, V, WX; RW1)),
    (0x54, 1, op!(Andpd, V, WX; RW1)),
    (0x55, 0, op!(Andnps, V, WX; RW1)),
    (0x55, 1, op!(Andnpd, V, WX; RW1)),
    (0x56, 0, op!(Orps, V, WX; RW1)),
    (0x56, 1, op!(Orpd, V, WX; RW1)),
    (0x57, 0, op!(Xorps, V, WX; RW1)),
    (0x57, 1, op!(Xorpd, V, WX; RW1)),
    (0x5a, 0, op!(Cvtps2pd, V, WQ; W1)),
    (0x5a, 1, op!(Cvtpd2ps, V, WX; W1)),
    (0x5a, 2, op!(Cvtss2sd, V, WD; RW1)),
    (0x5a, 3, op!(Cvtsd2ss, V, WQ; RW1)),
    (0x5b, 0, op!(Cvtdq2ps, V, WX; W1)),
    (0x5b, 1, op!(Cvtps2dq, V, WX; W1)),
    (0x5b, 2, op!(Cvttps2dq, V, WX; W1)),
    (0x6c, 1, op!(Punpcklqdq, V, WX; RW1)),
    (0x6d, 1, op!(Punpckhqdq, V, WX; RW1)),
    (0x6e, 0, op!(Movd, P, EY; W1 | MOVQ)),
    (0x6e, 1, op!(Movd, V, EY; W1 | MOVQ)),
    (0x6f, 0, op!(Movq, P, QQ; W1)),
    (0x6f, 1, op!(Movdqa, V, WX; W1)),
    (0x6f, 2, op!(Movdqu, V, WX; W1)),
    (0x70, 0, op!(Pshufw, P, QQ, IB; W1)),
    (0x70, 1, op!(Pshufd, V, WX, IB; W1)),
    (0x70, 2, op!(Pshufhw, V, WX, IB; W1)),
    (0x70, 3, op!(Pshuflw, V, WX, IB; W1)),
    (0x71, 0, grp!(g::G12P)),
    (0x71, 1, grp!(g::G12X)),
    (0x72, 0, grp!(g::G13P)),
    (0x72, 1, grp!(g::G13X)),
    (0x73, 0, grp!(g::G14P)),
    (0x73, 1, grp!(g::G14X)),
    (0x77, 0, op!(Emms; 0)),
    (0x78, 0, op!(Vmread, EQ, GQ; W1)),
    (0x78, 1, op!(Extrq, U, IB, I2; RW1 | REGF)),
    (0x78, 3, op!(Insertq, V, U, IB, I2; RW1 | REGF)),
    (0x79, 0, op!(Vmwrite, GQ, EQ; W1)),
    (0x79, 1, op!(Extrq, V, U; RW1 | REGF)),
    (0x79, 3, op!(Insertq, V, U; RW1 | REGF)),
    (0x7c, 1, op!(Haddpd, V, WX; RW1)),
    (0x7c, 3, op!(Haddps, V, WX; RW1)),
    (0x7d, 1, op!(Hsubpd, V, WX; RW1)),
    (0x7d, 3, op!(Hsubps, V, WX; RW1)),
    (0x7e, 0, op!(Movd, EY, P; W1 | MOVQ)),
    (0x7e, 1, op!(Movd, EY, V; W1 | MOVQ)),
    (0x7e, 2, op!(Movq, V, WQ; W1)),
    (0x7f, 0, op!(Movq, QQ, P; W1)),
    (0x7f, 1, op!(Movdqa, WX, V; W1)),
    (0x7f, 2, op!(Movdqu, WX, V; W1)),
    (0xa0, 0, op!(Push, FS; D64)),
    (0xa1, 0, op!(Pop, FS; D64 | W1)),
    (0xa2, 0, op!(Cpuid; 0)),
    (0xa3, 0, op!(Bt, EV, GV; 0)),
    (0xa4, 0, op!(Shld, EV, GV, IB; RW1)),
    (0xa5, 0, op!(Shld, EV, GV, CL; RW1)),
    (0xa8, 0, op!(Push, GS; D64)),
    (0xa9, 0, op!(Pop, GS; D64 | W1)),
    (0xaa, 0, op!(Rsm; 0)),
    (0xab, 0, op!(Bts, EV, GV; RW1 | LOCK)),
    (0xac, 0, op!(Shrd, EV, GV, IB; RW1)),
    (0xad, 0, op!(Shrd, EV, GV, CL; RW1)),
    (0xae, 0, special!(s::G15)),
    (0xaf, 0, op!(Imul, GV, EV; RW1)),
    (0xb0, 0, op!(Cmpxchg, EB, GB; RW1 | LOCK)),
    (0xb1, 0, op!(Cmpxchg, EV, GV; RW1 | LOCK)),
    (0xb2, 0, op!(Lss, GV, MP; W1)),
    (0xb3, 0, op!(Btr, EV, GV; RW1 | LOCK)),
    (0xb4, 0, op!(Lfs, GV, MP; W1)),
    (0xb5, 0, op!(Lgs, GV, MP; W1)),
    (0xb6, 0, op!(Movzx, GV, EB; W1)),
    (0xb7, 0, op!(Movzx, GV, EW; W1)),
    (0xb8, 2, op!(Popcnt, GV, EV; W1)),
    (0xb9, 0, op!(Ud1, GV, EV; 0)),
    (0xba, 0, grp!(g::G8)),
    (0xbb, 0, op!(Btc, EV, GV; RW1 | LOCK)),
    (0xbc, 0, op!(Bsf, GV, EV; RW1)),
    (0xbc, 2, op!(Tzcnt, GV, EV; W1)),
    (0xbd, 0, op!(Bsr, GV, EV; RW1)),
    (0xbd, 2, op!(Lzcnt, GV, EV; W1)),
    (0xbe, 0, op!(Movsx, GV, EB; W1)),
    (0xbf, 0, op!(Movsx, GV, EW; W1)),
    (0xc0, 0, op!(Xadd, EB, GB; RW2 | LOCK)),
    (0xc1, 0, op!(Xadd, EV, GV; RW2 | LOCK)),
    (0xc2, 0, op!(Cmpps, V, WX, IB; RW1)),
    (0xc2, 1, op!(Cmppd, V, WX, IB; RW1)),
    (0xc2, 2, op!(Cmpss, V, WD, IB; RW1)),
    (0xc2, 3, op!(Cmpsd, V, WQ, IB; RW1)),
    (0xc3, 0, op!(Movnti, MY, GY; W1)),
    (0xc4, 0, op!(Pinsrw, P, EWD, IB; RW1)),
    (0xc4, 1, op!(Pinsrw, V, EWD, IB; RW1)),
    (0xc5, 0, op!(Pextrw, GD, N, IB; W1)),
    (0xc5, 1, op!(Pextrw, GD, U, IB; W1)),
    (0xc6, 0, op!(Shufps, V, WX, IB; RW1)),
    (0xc6, 1, op!(Shufpd, V, WX, IB; RW1)),
    (0xc7, 0, special!(s::G9)),
    (0xd0, 1, op!(Addsubpd, V, WX; RW1)),
    (0xd0, 3, op!(Addsubps, V, WX; RW1)),
    (0xd6, 1, op!(Movq, WQ, V; W1)),
    (0xd6, 2, op!(Movq2dq, V, N; W1)),
    (0xd6, 3, op!(Movdq2q, P, U; W1)),
    (0xd7, 0, op!(Pmovmskb, GD, N; W1)),
    (0xd7, 1, op!(Pmovmskb, GD, U; W1)),
    (0xe6, 1, op!(Cvttpd2dq, V, WX; W1)),
    (0xe6, 2, op!(Cvtdq2pd, V, WQ; W1)),
    (0xe6, 3, op!(Cvtpd2dq, V, WX; W1)),
    (0xe7, 0, op!(Movntq, MQ, P; W1)),
    (0xe7, 1, op!(Movntdq, MX, V; W1)),
    (0xf0, 3, op!(Lddqu, V, M0; W1)),
    (0xf7, 0, op!(Maskmovq, P, N; 0)),
    (0xf7, 1, op!(Maskmovdqu, V, U; 0)),
    (0xff, 0, op!(Ud0, GV, EV; 0)),
];

/// The packed integer opcodes: MMX without a prefix, XMM with `66`.
const PACKED: &[(u8, Mnem)] = &[
    (0x60, Punpcklbw),
    (0x61, Punpcklwd),
    (0x62, Punpckldq),
    (0x63, Packsswb),
    (0x64, Pcmpgtb),
    (0x65, Pcmpgtw),
    (0x66, Pcmpgtd),
    (0x67, Packuswb),
    (0x68, Punpckhbw),
    (0x69, Punpckhwd),
    (0x6a, Punpckhdq),
    (0x6b, Packssdw),
    (0x74, Pcmpeqb),
    (0x75, Pcmpeqw),
    (0x76, Pcmpeqd),
    (0xd1, Psrlw),
    (0xd2, Psrld),
    (0xd3, Psrlq),
    (0xd4, Paddq),
    (0xd5, Pmullw),
    (0xd8, Psubusb),
    (0xd9, Psubusw),
    (0xda, Pminub),
    (0xdb, Pand),
    (0xdc, Paddusb),
    (0xdd, Paddusw),
    (0xde, Pmaxub),
    (0xdf, Pandn),
    (0xe0, Pavgb),
    (0xe1, Psraw),
    (0xe2, Psrad),
    (0xe3, Pavgw),
    (0xe4, Pmulhuw),
    (0xe5, Pmulhw),
    (0xe8, Psubsb),
    (0xe9, Psubsw),
    (0xea, Pminsw),
    (0xeb, Por),
    (0xec, Paddsb),
    (0xed, Paddsw),
    (0xee, Pmaxsw),
    (0xef, Pxor),
    (0xf1, Psllw),
    (0xf2, Pslld),
    (0xf3, Psllq),
    (0xf4, Pmuludq),
    (0xf5, Pmaddwd),
    (0xf6, Psadbw),
    (0xf8, Psubb),
    (0xf9, Psubw),
    (0xfa, Psubd),
    (0xfb, Psubq),
    (0xfc, Paddb),
    (0xfd, Paddw),
    (0xfe, Paddd),
];

/// The arithmetic opcodes with four forms: `ps`, `pd`, `ss` and `sd`.
const ARITH: &[(u8, [Mnem; 4])] = &[
    (0x58, [Addps, Addpd, Addss, Addsd]),
    (0x59, [Mulps, Mulpd, Mulss, Mulsd]),
    (0x5c, [Subps, Subpd, Subss, Subsd]),
    (0x5d, [Minps, Minpd, Minss, Minsd]),
    (0x5e, [Divps, Divpd, Divss, Divsd]),
    (0x5f, [Maxps, Maxpd, Maxss, Maxsd]),
];

const CMOV: [Mnem; 16] = [
    Cmovo, Cmovno, Cmovb, Cmovae, Cmove, Cmovne, Cmovbe, Cmova, Cmovs, Cmovns, Cmovp, Cmovnp,
    Cmovl, Cmovge, Cmovle, Cmovg,
];

const SETCC: [Mnem; 16] = [
    Seto, Setno, Setb, Setae, Sete, Setne, Setbe, Seta, Sets, Setns, Setp, Setnp, Setl, Setge,
    Setle, Setg,
];

const JCC: [Mnem; 16] = [
    Jo, Jno, Jb, Jae, Je, Jne, Jbe, Ja, Js, Jns, Jp, Jnp, Jl, Jge, Jle, Jg,
];

/// The rows of the `0F` map in four prefix columns.
pub(crate) const MAP1: [[Entry; 4]; 256] = {
    let mut t = [[UNDEF; 4]; 256];
    let mut i = 0;
    while i < 16 {
        t[0x40 + i] = [op!(CMOV[i], GV, EV; RW1), UNDEF, UNDEF, UNDEF];
        t[0x80 + i] = [op!(JCC[i], JZ; 0), UNDEF, UNDEF, UNDEF];
        t[0x90 + i] = [op!(SETCC[i], EB; W1), UNDEF, UNDEF, UNDEF];
        i += 1;
    }
    i = 0;
    while i < 8 {
        t[0xc8 + i] = [op!(Bswap, ZY; RW1), UNDEF, UNDEF, UNDEF];
        i += 1;
    }
    i = 0;
    while i < PACKED.len() {
        let (op, m) = PACKED[i];
        // The low unpacks read 32 bits of an MMX memory operand.
        let q = if op <= 0x62 { QD } else { QQ };
        t[op as usize][0] = op!(m, P, q; RW1);
        t[op as usize][1] = op!(m, V, WX; RW1);
        i += 1;
    }
    i = 0;
    while i < ARITH.len() {
        let (op, m) = ARITH[i];
        t[op as usize] = [
            op!(m[0], V, WX; RW1),
            op!(m[1], V, WX; RW1),
            op!(m[2], V, WD; RW1),
            op!(m[3], V, WQ; RW1),
        ];
        i += 1;
    }
    i = 0;
    while i < ROWS.len() {
        let (op, col, e) = ROWS[i];
        t[op as usize][col as usize] = e;
        i += 1;
    }
    t
};
