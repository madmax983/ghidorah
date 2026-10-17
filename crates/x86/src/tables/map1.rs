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

const fn np(op: u8, e: Entry) -> Row {
    (op, 0, e)
}

const fn x66(op: u8, e: Entry) -> Row {
    (op, 1, e)
}

const fn xf3(op: u8, e: Entry) -> Row {
    (op, 2, e)
}

const fn xf2(op: u8, e: Entry) -> Row {
    (op, 3, e)
}

const fn mov(m: Mnem, a: Spec, b: Spec) -> Entry {
    op2(m, a, b, W1)
}

const fn alu(m: Mnem, a: Spec, b: Spec) -> Entry {
    op2(m, a, b, RW1)
}

const ROWS: &[Row] = &[
    np(0x00, grp(g::G6)),
    np(0x01, special(s::G7)),
    np(0x02, op2(Lar, GV, EWV, W1)),
    np(0x03, op2(Lsl, GV, EWV, W1)),
    np(0x05, op0(Syscall, 0)),
    np(0x06, op0(Clts, 0)),
    np(0x07, op0(Sysret, 0)),
    np(0x08, op0(Invd, 0)),
    np(0x09, op0(Wbinvd, 0)),
    np(0x0b, op0(Ud2, 0)),
    np(0x0d, grp(g::G0D)),
    np(0x0e, op0(Femms, 0)),
    np(0x0f, OPAQUE),
    np(0x10, mov(Movups, V, WX)),
    x66(0x10, mov(Movupd, V, WX)),
    xf3(0x10, mov(Movss, V, WD)),
    xf2(0x10, mov(Movsd, V, WQ)),
    np(0x11, mov(Movups, WX, V)),
    x66(0x11, mov(Movupd, WX, V)),
    xf3(0x11, mov(Movss, WD, V)),
    xf2(0x11, mov(Movsd, WQ, V)),
    np(0x12, special(s::MOVLPS12)),
    x66(0x12, alu(Movlpd, V, MQ)),
    xf3(0x12, mov(Movsldup, V, WX)),
    xf2(0x12, mov(Movddup, V, WQ)),
    np(0x13, mov(Movlps, MQ, V)),
    x66(0x13, mov(Movlpd, MQ, V)),
    np(0x14, alu(Unpcklps, V, WX)),
    x66(0x14, alu(Unpcklpd, V, WX)),
    np(0x15, alu(Unpckhps, V, WX)),
    x66(0x15, alu(Unpckhpd, V, WX)),
    np(0x16, special(s::MOVHPS16)),
    x66(0x16, alu(Movhpd, V, MQ)),
    xf3(0x16, mov(Movshdup, V, WX)),
    np(0x17, mov(Movhps, MQ, V)),
    x66(0x17, mov(Movhpd, MQ, V)),
    np(0x18, special(s::HINT18)),
    np(0x19, op1(Nop, EV, ADDR)),
    np(0x1a, op1(Nop, EV, ADDR)),
    np(0x1b, op1(Nop, EV, ADDR)),
    np(0x1c, special(s::HINT1C)),
    np(0x1d, op1(Nop, EV, ADDR)),
    np(0x1e, op1(Nop, EV, ADDR)),
    xf3(0x1e, special(s::HINT1E)),
    np(0x1f, op1(Nop, EV, ADDR)),
    np(0x20, mov(Mov, RQ, CR)),
    np(0x21, mov(Mov, RQ, DR)),
    np(0x22, mov(Mov, CR, RQ)),
    np(0x23, mov(Mov, DR, RQ)),
    np(0x28, mov(Movaps, V, WX)),
    x66(0x28, mov(Movapd, V, WX)),
    np(0x29, mov(Movaps, WX, V)),
    x66(0x29, mov(Movapd, WX, V)),
    np(0x2a, alu(Cvtpi2ps, V, QQ)),
    x66(0x2a, mov(Cvtpi2pd, V, QQ)),
    xf3(0x2a, alu(Cvtsi2ss, V, EY)),
    xf2(0x2a, alu(Cvtsi2sd, V, EY)),
    np(0x2b, mov(Movntps, MX, V)),
    x66(0x2b, mov(Movntpd, MX, V)),
    np(0x2c, mov(Cvttps2pi, P, WQ)),
    x66(0x2c, mov(Cvttpd2pi, P, WX)),
    xf3(0x2c, mov(Cvttss2si, GY, WD)),
    xf2(0x2c, mov(Cvttsd2si, GY, WQ)),
    np(0x2d, mov(Cvtps2pi, P, WQ)),
    x66(0x2d, mov(Cvtpd2pi, P, WX)),
    xf3(0x2d, mov(Cvtss2si, GY, WD)),
    xf2(0x2d, mov(Cvtsd2si, GY, WQ)),
    np(0x2e, op2(Ucomiss, V, WD, 0)),
    x66(0x2e, op2(Ucomisd, V, WQ, 0)),
    np(0x2f, op2(Comiss, V, WD, 0)),
    x66(0x2f, op2(Comisd, V, WQ, 0)),
    np(0x30, op0(Wrmsr, 0)),
    np(0x31, op0(Rdtsc, 0)),
    np(0x32, op0(Rdmsr, 0)),
    np(0x33, op0(Rdpmc, 0)),
    np(0x34, op0(Sysenter, 0)),
    np(0x35, op0(Sysexit, 0)),
    np(0x37, special(s::UNSUP)),
    np(0x50, mov(Movmskps, GD, U)),
    x66(0x50, mov(Movmskpd, GD, U)),
    np(0x51, mov(Sqrtps, V, WX)),
    x66(0x51, mov(Sqrtpd, V, WX)),
    xf3(0x51, alu(Sqrtss, V, WD)),
    xf2(0x51, alu(Sqrtsd, V, WQ)),
    np(0x52, mov(Rsqrtps, V, WX)),
    xf3(0x52, alu(Rsqrtss, V, WD)),
    np(0x53, mov(Rcpps, V, WX)),
    xf3(0x53, alu(Rcpss, V, WD)),
    np(0x54, alu(Andps, V, WX)),
    x66(0x54, alu(Andpd, V, WX)),
    np(0x55, alu(Andnps, V, WX)),
    x66(0x55, alu(Andnpd, V, WX)),
    np(0x56, alu(Orps, V, WX)),
    x66(0x56, alu(Orpd, V, WX)),
    np(0x57, alu(Xorps, V, WX)),
    x66(0x57, alu(Xorpd, V, WX)),
    np(0x5a, mov(Cvtps2pd, V, WQ)),
    x66(0x5a, mov(Cvtpd2ps, V, WX)),
    xf3(0x5a, alu(Cvtss2sd, V, WD)),
    xf2(0x5a, alu(Cvtsd2ss, V, WQ)),
    np(0x5b, mov(Cvtdq2ps, V, WX)),
    x66(0x5b, mov(Cvtps2dq, V, WX)),
    xf3(0x5b, mov(Cvttps2dq, V, WX)),
    x66(0x6c, alu(Punpcklqdq, V, WX)),
    x66(0x6d, alu(Punpckhqdq, V, WX)),
    np(0x6e, op2(Movd, P, EY, W1 | MOVQ)),
    x66(0x6e, op2(Movd, V, EY, W1 | MOVQ)),
    np(0x6f, mov(Movq, P, QQ)),
    x66(0x6f, mov(Movdqa, V, WX)),
    xf3(0x6f, mov(Movdqu, V, WX)),
    np(0x70, op3(Pshufw, P, QQ, IB, W1)),
    x66(0x70, op3(Pshufd, V, WX, IB, W1)),
    xf3(0x70, op3(Pshufhw, V, WX, IB, W1)),
    xf2(0x70, op3(Pshuflw, V, WX, IB, W1)),
    np(0x71, grp(g::G12P)),
    x66(0x71, grp(g::G12X)),
    np(0x72, grp(g::G13P)),
    x66(0x72, grp(g::G13X)),
    np(0x73, grp(g::G14P)),
    x66(0x73, grp(g::G14X)),
    np(0x77, op0(Emms, 0)),
    np(0x78, op2(Vmread, EQ, GQ, W1)),
    x66(0x78, op3(Extrq, U, IB, I2, RW1)),
    xf2(0x78, op4(Insertq, V, U, IB, I2, RW1)),
    np(0x79, op2(Vmwrite, GQ, EQ, W1)),
    x66(0x7c, alu(Haddpd, V, WX)),
    xf2(0x7c, alu(Haddps, V, WX)),
    x66(0x7d, alu(Hsubpd, V, WX)),
    xf2(0x7d, alu(Hsubps, V, WX)),
    np(0x7e, op2(Movd, EY, P, W1 | MOVQ)),
    x66(0x7e, op2(Movd, EY, V, W1 | MOVQ)),
    xf3(0x7e, mov(Movq, V, WQ)),
    np(0x7f, mov(Movq, QQ, P)),
    x66(0x7f, mov(Movdqa, WX, V)),
    xf3(0x7f, mov(Movdqu, WX, V)),
    np(0xa0, op1(Push, FS, D64)),
    np(0xa1, op1(Pop, FS, D64 | W1)),
    np(0xa2, op0(Cpuid, 0)),
    np(0xa3, op2(Bt, EV, GV, 0)),
    np(0xa4, op3(Shld, EV, GV, IB, RW1)),
    np(0xa5, op3(Shld, EV, GV, CL, RW1)),
    np(0xa8, op1(Push, GS, D64)),
    np(0xa9, op1(Pop, GS, D64 | W1)),
    np(0xaa, op0(Rsm, 0)),
    np(0xab, op2(Bts, EV, GV, RW1 | LOCK)),
    np(0xac, op3(Shrd, EV, GV, IB, RW1)),
    np(0xad, op3(Shrd, EV, GV, CL, RW1)),
    np(0xae, special(s::G15)),
    np(0xaf, alu(Imul, GV, EV)),
    np(0xb0, op2(Cmpxchg, EB, GB, RW1 | LOCK)),
    np(0xb1, op2(Cmpxchg, EV, GV, RW1 | LOCK)),
    np(0xb2, mov(Lss, GV, MP)),
    np(0xb3, op2(Btr, EV, GV, RW1 | LOCK)),
    np(0xb4, mov(Lfs, GV, MP)),
    np(0xb5, mov(Lgs, GV, MP)),
    np(0xb6, mov(Movzx, GV, EB)),
    np(0xb7, mov(Movzx, GV, EW)),
    xf3(0xb8, mov(Popcnt, GV, EV)),
    np(0xb9, op2(Ud1, GV, EV, 0)),
    np(0xba, grp(g::G8)),
    np(0xbb, op2(Btc, EV, GV, RW1 | LOCK)),
    np(0xbc, alu(Bsf, GV, EV)),
    xf3(0xbc, mov(Tzcnt, GV, EV)),
    np(0xbd, alu(Bsr, GV, EV)),
    xf3(0xbd, mov(Lzcnt, GV, EV)),
    np(0xbe, mov(Movsx, GV, EB)),
    np(0xbf, mov(Movsx, GV, EW)),
    np(0xc0, op2(Xadd, EB, GB, RW2 | LOCK)),
    np(0xc1, op2(Xadd, EV, GV, RW2 | LOCK)),
    np(0xc2, op3(Cmpps, V, WX, IB, RW1)),
    x66(0xc2, op3(Cmppd, V, WX, IB, RW1)),
    xf3(0xc2, op3(Cmpss, V, WD, IB, RW1)),
    xf2(0xc2, op3(Cmpsd, V, WQ, IB, RW1)),
    np(0xc3, mov(Movnti, MY, GY)),
    np(0xc4, op3(Pinsrw, P, EWD, IB, RW1)),
    x66(0xc4, op3(Pinsrw, V, EWD, IB, RW1)),
    np(0xc5, op3(Pextrw, GD, N, IB, W1)),
    x66(0xc5, op3(Pextrw, GD, U, IB, W1)),
    np(0xc6, op3(Shufps, V, WX, IB, RW1)),
    x66(0xc6, op3(Shufpd, V, WX, IB, RW1)),
    np(0xc7, special(s::G9)),
    x66(0xd0, alu(Addsubpd, V, WX)),
    xf2(0xd0, alu(Addsubps, V, WX)),
    x66(0xd6, mov(Movq, WQ, V)),
    xf3(0xd6, mov(Movq2dq, V, N)),
    xf2(0xd6, mov(Movdq2q, P, U)),
    np(0xd7, mov(Pmovmskb, GD, N)),
    x66(0xd7, mov(Pmovmskb, GD, U)),
    x66(0xe6, mov(Cvttpd2dq, V, WX)),
    xf3(0xe6, mov(Cvtdq2pd, V, WQ)),
    xf2(0xe6, mov(Cvtpd2dq, V, WX)),
    np(0xe7, mov(Movntq, MQ, P)),
    x66(0xe7, mov(Movntdq, MX, V)),
    xf2(0xf0, mov(Lddqu, V, M0)),
    np(0xf7, op2(Maskmovq, P, N, 0)),
    x66(0xf7, op2(Maskmovdqu, V, U, 0)),
    np(0xff, op2(Ud0, GV, EV, 0)),
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

const fn build() -> [[Entry; 4]; 256] {
    let mut t = [[UNDEF; 4]; 256];
    let mut i = 0;
    while i < 16 {
        t[0x40 + i] = [op2(CMOV[i], GV, EV, RW1), UNDEF, UNDEF, UNDEF];
        t[0x80 + i] = [op1(JCC[i], JZ, 0), UNDEF, UNDEF, UNDEF];
        t[0x90 + i] = [op1(SETCC[i], EB, W1), UNDEF, UNDEF, UNDEF];
        i += 1;
    }
    i = 0;
    while i < 8 {
        t[0xc8 + i] = [op1(Bswap, ZY, RW1), UNDEF, UNDEF, UNDEF];
        i += 1;
    }
    i = 0;
    while i < PACKED.len() {
        let (op, m) = PACKED[i];
        // The low unpacks read 32 bits of an MMX memory operand.
        let q = if op <= 0x62 { QD } else { QQ };
        t[op as usize][0] = op2(m, P, q, RW1);
        t[op as usize][1] = op2(m, V, WX, RW1);
        i += 1;
    }
    i = 0;
    while i < ARITH.len() {
        let (op, m) = ARITH[i];
        t[op as usize] = [
            op2(m[0], V, WX, RW1),
            op2(m[1], V, WX, RW1),
            op2(m[2], V, WD, RW1),
            op2(m[3], V, WQ, RW1),
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
}

/// The rows of the `0F` map in four prefix columns.
pub(crate) const MAP1: [[Entry; 4]; 256] = build();
