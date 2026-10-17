//! The mnemonic table of the lifter (design Section 6.3).
//!
//! Each row maps one canonical mnemonic to a template, a flag operation, a write flag and a
//! width rule. A mnemonic without a row lifts to `Intrinsic` or `Unimpl`.

use FlagOp as F;
use Template as T;
use WidthRule::{Dst, Fixed};
use ghidorah_ir::FlagOp;

use super::{Row, Template, WidthRule};
use crate::Mnem;

/// Makes a row.
const fn r(
    mnem: Mnem,
    template: Template,
    flag_op: Option<FlagOp>,
    writes_dst: bool,
    width: WidthRule,
) -> Row {
    Row {
        mnem,
        template,
        flag_op,
        writes_dst,
        width,
    }
}

const ADD: Option<FlagOp> = Some(F::X86Add);
const SUB: Option<FlagOp> = Some(F::X86Sub);
const LOGIC: Option<FlagOp> = Some(F::X86Logic);
const NONE: Option<FlagOp> = None;

/// The rows in template order.
pub(super) const ROWS: &[Row] = &[
    // alu2
    r(Mnem::Add, T::Alu2, ADD, true, Dst),
    r(Mnem::Or, T::Alu2, LOGIC, true, Dst),
    r(Mnem::Adc, T::Alu2, Some(F::X86Adc), true, Dst),
    r(Mnem::Sbb, T::Alu2, Some(F::X86Sbb), true, Dst),
    r(Mnem::And, T::Alu2, LOGIC, true, Dst),
    r(Mnem::Sub, T::Alu2, SUB, true, Dst),
    r(Mnem::Xor, T::Alu2, LOGIC, true, Dst),
    r(Mnem::Cmp, T::Alu2, SUB, false, Dst),
    r(Mnem::Test, T::Alu2, LOGIC, false, Dst),
    // alu1
    r(Mnem::Inc, T::Alu1, Some(F::X86Inc), true, Dst),
    r(Mnem::Dec, T::Alu1, Some(F::X86Dec), true, Dst),
    r(Mnem::Neg, T::Alu1, Some(F::X86Neg), true, Dst),
    r(Mnem::Not, T::Alu1, NONE, true, Dst),
    // mov
    r(Mnem::Mov, T::Mov, NONE, true, Dst),
    r(Mnem::Movabs, T::Mov, NONE, true, Dst),
    // movx
    r(Mnem::Movzx, T::Movx, NONE, true, Dst),
    r(Mnem::Movsx, T::Movx, NONE, true, Dst),
    r(Mnem::Movsxd, T::Movx, NONE, true, Dst),
    // lea
    r(Mnem::Lea, T::Lea, NONE, true, Dst),
    // cmov
    r(Mnem::Cmovo, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovno, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovb, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovae, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmove, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovne, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovbe, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmova, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovs, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovns, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovp, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovnp, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovl, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovge, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovle, T::Cmov, NONE, true, Dst),
    r(Mnem::Cmovg, T::Cmov, NONE, true, Dst),
    // setcc
    r(Mnem::Seto, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setno, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setb, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setae, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Sete, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setne, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setbe, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Seta, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Sets, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setns, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setp, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setnp, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setl, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setge, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setle, T::Setcc, NONE, true, Fixed(8)),
    r(Mnem::Setg, T::Setcc, NONE, true, Fixed(8)),
    // branch
    r(Mnem::Jo, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jno, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jb, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jae, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Je, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jne, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jbe, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Ja, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Js, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jns, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jp, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jnp, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jl, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jge, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jle, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jg, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jmp, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Call, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Ret, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Loop, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Loope, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Loopne, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jrcxz, T::Branch, NONE, false, Fixed(64)),
    r(Mnem::Jecxz, T::Branch, NONE, false, Fixed(64)),
    // shift
    r(Mnem::Shl, T::Shift, Some(F::X86Shl), true, Dst),
    r(Mnem::Shr, T::Shift, Some(F::X86Shr), true, Dst),
    r(Mnem::Sar, T::Shift, Some(F::X86Sar), true, Dst),
    r(Mnem::Rol, T::Shift, Some(F::X86Rol), true, Dst),
    r(Mnem::Ror, T::Shift, Some(F::X86Ror), true, Dst),
    r(Mnem::Shld, T::Shift, Some(F::X86Shl), true, Dst),
    r(Mnem::Shrd, T::Shift, Some(F::X86Shr), true, Dst),
    // muldiv
    r(Mnem::Mul, T::MulDiv, Some(F::X86UMul), true, Dst),
    r(Mnem::Imul, T::MulDiv, Some(F::X86SMul), true, Dst),
    r(Mnem::Div, T::MulDiv, NONE, true, Dst),
    r(Mnem::Idiv, T::MulDiv, NONE, true, Dst),
    // stack
    r(Mnem::Push, T::Stack, NONE, false, Dst),
    r(Mnem::Pop, T::Stack, NONE, true, Dst),
    r(Mnem::Leave, T::Stack, NONE, true, Fixed(64)),
    r(Mnem::Pushf, T::Stack, NONE, false, Fixed(64)),
    r(Mnem::Popf, T::Stack, NONE, false, Fixed(64)),
    // string
    r(Mnem::Movs, T::String, NONE, true, Dst),
    r(Mnem::Stos, T::String, NONE, true, Dst),
    r(Mnem::Lods, T::String, NONE, true, Dst),
    r(Mnem::Scas, T::String, SUB, false, Dst),
    r(Mnem::Cmps, T::String, SUB, false, Dst),
    // sse_move
    r(Mnem::Movd, T::SseMove, NONE, true, Fixed(32)),
    r(Mnem::Movq, T::SseMove, NONE, true, Fixed(64)),
    r(Mnem::Movaps, T::SseMove, NONE, true, Fixed(128)),
    r(Mnem::Movups, T::SseMove, NONE, true, Fixed(128)),
    r(Mnem::Movapd, T::SseMove, NONE, true, Fixed(128)),
    r(Mnem::Movupd, T::SseMove, NONE, true, Fixed(128)),
    r(Mnem::Movdqa, T::SseMove, NONE, true, Fixed(128)),
    r(Mnem::Movdqu, T::SseMove, NONE, true, Fixed(128)),
    r(Mnem::Movss, T::SseMove, NONE, true, Fixed(32)),
    r(Mnem::Movsd, T::SseMove, NONE, true, Fixed(64)),
    // sse_zero
    r(Mnem::Pxor, T::SseZero, NONE, true, Fixed(128)),
    r(Mnem::Xorps, T::SseZero, NONE, true, Fixed(128)),
    r(Mnem::Xorpd, T::SseZero, NONE, true, Fixed(128)),
    // single forms
    r(Mnem::Xchg, T::Single, NONE, true, Dst),
    r(Mnem::Cmpxchg, T::Single, SUB, true, Dst),
    r(Mnem::Xadd, T::Single, ADD, true, Dst),
    r(Mnem::Bswap, T::Single, NONE, true, Dst),
    r(Mnem::Bt, T::Single, Some(F::X86Bt), false, Dst),
    r(Mnem::Bts, T::Single, Some(F::X86Bt), true, Dst),
    r(Mnem::Btr, T::Single, Some(F::X86Bt), true, Dst),
    r(Mnem::Btc, T::Single, Some(F::X86Bt), true, Dst),
    r(Mnem::Bsf, T::Single, LOGIC, true, Dst),
    r(Mnem::Bsr, T::Single, LOGIC, true, Dst),
    r(Mnem::Popcnt, T::Single, NONE, true, Dst),
    r(Mnem::Lzcnt, T::Single, NONE, true, Dst),
    r(Mnem::Tzcnt, T::Single, NONE, true, Dst),
    r(Mnem::Cbw, T::Single, NONE, true, Fixed(16)),
    r(Mnem::Cwde, T::Single, NONE, true, Fixed(32)),
    r(Mnem::Cdqe, T::Single, NONE, true, Fixed(64)),
    r(Mnem::Cwd, T::Single, NONE, true, Fixed(16)),
    r(Mnem::Cdq, T::Single, NONE, true, Fixed(32)),
    r(Mnem::Cqo, T::Single, NONE, true, Fixed(64)),
    r(Mnem::Lahf, T::Single, NONE, true, Fixed(8)),
    r(Mnem::Sahf, T::Single, NONE, false, Fixed(8)),
    r(Mnem::Cmc, T::Single, NONE, false, Fixed(16)),
    r(Mnem::Clc, T::Single, NONE, false, Fixed(16)),
    r(Mnem::Stc, T::Single, NONE, false, Fixed(16)),
    r(Mnem::Cld, T::Single, NONE, false, Fixed(16)),
    r(Mnem::Endbr64, T::Single, NONE, false, Fixed(64)),
    r(Mnem::Nop, T::Single, NONE, false, Fixed(64)),
    r(Mnem::Pause, T::Single, NONE, false, Fixed(64)),
];

/// The row index of each mnemonic, or `u8::MAX` for a mnemonic without a row.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the table has fewer than 255 rows, and a test checks it"
)]
pub(super) const INDEX: [u8; Mnem::ALL.len()] = {
    let mut index = [u8::MAX; Mnem::ALL.len()];
    let mut i = 0;
    while i < ROWS.len() {
        index[ROWS[i].mnem as usize] = i as u8;
        i += 1;
    }
    index
};
