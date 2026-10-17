//! The forms of the `branch` vector file.
//!
//! A branch form jumps 4 bytes forward over the tail `lea r14, [r14+1]`. A call form calls
//! the next address, and the tail `lea r14, [rip]` gives the return address. A return form
//! writes the address after the `ret` to `[rsp]` first.

use crate::native::{Form, Rule};

/// One branch form over the 4-byte tail.
macro_rules! branch {
    ($row:literal, $name:expr, [$($b:literal),+], [$($r:ident),*], $cases:literal, $rule:expr) => {
        form!("branch", $row, 64, $name, Branch, [] [$($b),+] [0x4d, 0x8d, 0x76, 0x01],
            [$($r),*], [], 0, $cases, $rule)
    };
}

/// One `jcc rel8` form for each condition.
macro_rules! jcc_rows {
    ($($row:literal $o:literal;)*) => {
        &[$(
            branch!($row, concat!($row, " rel8"), [$o, 0x04], [Flags, Pc], 64, Rule::Free),
        )*]
    };
}

/// The `jcc` rows.
pub(super) const JCC: &[Form] = jcc_rows! {
    "jo" 0x70; "jno" 0x71; "jb" 0x72; "jae" 0x73;
    "je" 0x74; "jne" 0x75; "jbe" 0x76; "ja" 0x77;
    "js" 0x78; "jns" 0x79; "jp" 0x7a; "jnp" 0x7b;
    "jl" 0x7c; "jge" 0x7d; "jle" 0x7e; "jg" 0x7f;
};

/// The other `branch` rows.
pub(super) const BRANCH: &[Form] = &[
    branch!(
        "je",
        "je rel32",
        [0x0f, 0x84, 0x04, 0x00, 0x00, 0x00],
        [Flags, Pc],
        16,
        Rule::Free
    ),
    branch!("jmp", "jmp rel8", [0xeb, 0x04], [Flags, Pc], 64, Rule::Free),
    branch!(
        "jmp",
        "jmp rel32",
        [0xe9, 0x04, 0x00, 0x00, 0x00],
        [Flags, Pc],
        16,
        Rule::Free
    ),
    branch!(
        "loop",
        "loop rel8",
        [0xe2, 0x04],
        [Rcx, Flags, Pc],
        64,
        Rule::Free
    ),
    branch!(
        "loope",
        "loope rel8",
        [0xe1, 0x04],
        [Rcx, Flags, Pc],
        64,
        Rule::Free
    ),
    branch!(
        "loopne",
        "loopne rel8",
        [0xe0, 0x04],
        [Rcx, Flags, Pc],
        64,
        Rule::Free
    ),
    branch!(
        "jrcxz",
        "jrcxz rel8",
        [0xe3, 0x04],
        [Rcx, Flags, Pc],
        64,
        Rule::Free
    ),
    branch!(
        "jecxz",
        "jecxz rel8",
        [0x67, 0xe3, 0x04],
        [Rcx, Flags, Pc],
        64,
        Rule::Free
    ),
    form!("branch", "call", 64, "call rel32", Call,
        [] [0xe8, 0x00, 0x00, 0x00, 0x00] [0x4c, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00],
        [Rsp, Flags, Pc], [Rsp = 32], 64, 64, Rule::Free),
    form!("branch", "ret", 64, "ret", Ret,
        [0x4c, 0x8d, 0x35, 0x05, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x34, 0x24] [0xc3] [],
        [Rsp, Flags], [Rsp = 16], 64, 64, Rule::Free),
    form!("branch", "ret", 64, "ret 0x10", Ret,
        [0x4c, 0x8d, 0x35, 0x07, 0x00, 0x00, 0x00, 0x4c, 0x89, 0x34, 0x24] [0xc2, 0x10, 0x00] [],
        [Rsp, Flags], [Rsp = 16], 64, 16, Rule::Free),
];
