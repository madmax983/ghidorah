//! The form tables of the native oracle, one module for each vector file.
//!
//! [`harness!`] makes the harness of one form. The harness saves `rbx`, `rbp` and the stack
//! pointer, loads the state that `r15` points to, runs the pre bytes, the instruction bytes
//! and the tail bytes, and stores the state again. No form uses `r15`.

use super::Form;

/// Makes the harness of a form: `[pre] [instruction] [tail]` bytes.
macro_rules! harness {
    ([$($p:literal),*] [$($b:literal),+] [$($t:literal),*]) => {{
        unsafe fn run(s: *mut $crate::native::State) {
            // SAFETY: the caller gives a valid state. The harness restores `rbx`, `rbp` and
            // `rsp`, and the form bytes touch only registers and the buffer of the state.
            unsafe {
                ::core::arch::asm!(
                    "push rbx",
                    "push rbp",
                    "mov [r15 + 200], rsp",
                    "movdqu xmm0, [r15 + 136]",
                    "movdqu xmm1, [r15 + 152]",
                    "movdqu xmm2, [r15 + 168]",
                    "movdqu xmm3, [r15 + 184]",
                    "push qword ptr [r15 + 128]",
                    "popfq",
                    "mov rax, [r15 + 0]",
                    "mov rcx, [r15 + 8]",
                    "mov rdx, [r15 + 16]",
                    "mov rbx, [r15 + 24]",
                    "mov rsp, [r15 + 32]",
                    "mov rbp, [r15 + 40]",
                    "mov rsi, [r15 + 48]",
                    "mov rdi, [r15 + 56]",
                    "mov r8, [r15 + 64]",
                    "mov r9, [r15 + 72]",
                    "mov r10, [r15 + 80]",
                    "mov r11, [r15 + 88]",
                    "mov r12, [r15 + 96]",
                    "mov r13, [r15 + 104]",
                    "mov r14, [r15 + 112]",
                    $(concat!(".byte ", stringify!($p)),)*
                    $(concat!(".byte ", stringify!($b)),)+
                    $(concat!(".byte ", stringify!($t)),)*
                    "mov [r15 + 0], rax",
                    "mov [r15 + 8], rcx",
                    "mov [r15 + 16], rdx",
                    "mov [r15 + 24], rbx",
                    "mov [r15 + 32], rsp",
                    "mov [r15 + 40], rbp",
                    "mov [r15 + 48], rsi",
                    "mov [r15 + 56], rdi",
                    "mov [r15 + 64], r8",
                    "mov [r15 + 72], r9",
                    "mov [r15 + 80], r10",
                    "mov [r15 + 88], r11",
                    "mov [r15 + 96], r12",
                    "mov [r15 + 104], r13",
                    "mov [r15 + 112], r14",
                    "mov rsp, [r15 + 200]",
                    "pushfq",
                    "pop qword ptr [r15 + 128]",
                    "movdqu [r15 + 136], xmm0",
                    "movdqu [r15 + 152], xmm1",
                    "movdqu [r15 + 168], xmm2",
                    "movdqu [r15 + 184], xmm3",
                    "pop rbp",
                    "pop rbx",
                    in("r15") s,
                    out("rax") _, out("rcx") _, out("rdx") _, out("rsi") _, out("rdi") _,
                    out("r8") _, out("r9") _, out("r10") _, out("r11") _, out("r12") _,
                    out("r13") _, out("r14") _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                );
            }
        }
        run as unsafe fn(*mut $crate::native::State)
    }};
}

/// Makes one form.
///
/// `form!(file, row, width, name, kind, [pre] [bytes] [tail], [regs], [ptrs], mem, cases,
/// rule)`.
macro_rules! form {
    (
        $file:literal, $row:literal, $w:literal, $name:expr, $kind:ident,
        [$($p:literal),*] [$($b:literal),+] [$($t:literal),*],
        [$($r:ident),*], [$($pr:ident = $po:literal),*], $mem:literal, $cases:literal, $rule:expr
    ) => {
        $crate::native::Form {
            file: $file,
            row: $row,
            w: $w,
            name: $name,
            kind: $crate::native::Kind::$kind,
            bytes: &[$($b),+],
            regs: &[$($crate::native::R::$r),*],
            ptrs: &[$(($crate::native::R::$pr, $po)),*],
            mem: $mem,
            cases: $cases,
            rule: $rule,
            run: harness!([$($p),*] [$($b),+] [$($t),*]),
        }
    };
}

/// Makes a plain form with no memory and no limit.
macro_rules! plain {
    ($file:literal, $row:literal, $w:literal, $name:expr, [$($b:literal),+], [$($r:ident),*], $cases:literal) => {
        form!($file, $row, $w, $name, Plain, [] [$($b),+] [], [$($r),*], [], 0, $cases, $crate::native::Rule::Free)
    };
}

mod alu;
mod branch;
mod data;
mod single;
mod sse;

/// The form families. Each family is one slice of forms.
pub(super) const FAMILIES: &[&[Form]] = &[
    alu::ALU2_ROWS,
    alu::ALU2,
    alu::ALU1_ROWS,
    alu::ALU1,
    alu::SHIFT,
    alu::SHIFT_DOUBLE,
    alu::MULDIV_ROWS,
    alu::MULDIV,
    data::MOV,
    data::MOVX,
    data::LEA,
    data::CMOV,
    data::SETCC,
    data::SETCC_MORE,
    data::STACK,
    data::STRING,
    branch::JCC,
    branch::BRANCH,
    sse::SSE_MOVE_FULL,
    sse::SSE_MOVE,
    sse::SSE_ZERO,
    single::BITS,
    single::EXCHANGE,
    single::SINGLE,
];
