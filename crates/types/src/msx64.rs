//! The Microsoft x64 calling convention of PE binaries (design Section 7.10, WP-30).
//!
//! The first four arguments are positional: argument n uses slot n of `rcx rdx r8 r9` for an
//! integer or a pointer, and slot n of `xmm0` to `xmm3` for a float or a double. Later
//! arguments are on the stack from `[rsp+0x28]` at entry, above the 32-byte shadow space of the
//! caller. The convention has no red zone and no varargs rule in the MVP.

use crate::cc::CallConv;

/// The Microsoft x64 convention of PE binaries.
pub const MS_X64: CallConv = CallConv {
    name: "ms_x64",
    int_args: &["rcx", "rdx", "r8", "r9"],
    float_args: &["xmm0", "xmm1", "xmm2", "xmm3"],
    int_ret: &["rax"],
    float_ret: &["xmm0"],
    callee_saved: &[
        "rbx", "rbp", "rdi", "rsi", "rsp", "r12", "r13", "r14", "r15", "xmm6", "xmm7", "xmm8",
        "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    ],
    positional: true,
    stack_arg_offset: 0x28,
    shadow_space: 32,
    red_zone: 0,
    stack_align: 16,
    return_pop: 8,
    varargs_reg: None,
};
