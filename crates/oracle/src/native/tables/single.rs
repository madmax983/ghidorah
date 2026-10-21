//! The forms of the `single` vector file: exchanges, bit operations, counts, sign
//! extensions, flag operations and `nop` forms.

use crate::native::{Form, Rule};

/// The 16-bit, 32-bit and 64-bit register forms of one `0F` row with `ModRM` `c1` or `c8`.
macro_rules! wide_rows {
    ($($row:literal [$($p:literal),*] $o:literal $m:literal;)*) => {
        &[$(
            plain!("single", $row, 16, concat!($row, " ax, cx"), [0x66, $($p,)* 0x0f, $o, $m], [Rax, Rcx, Flags], 64),
            plain!("single", $row, 32, concat!($row, " eax, ecx"), [$($p,)* 0x0f, $o, $m], [Rax, Rcx, Flags], 64),
            plain!("single", $row, 64, concat!($row, " rax, rcx"), [$($p,)* 0x48, 0x0f, $o, $m], [Rax, Rcx, Flags], 64),
        )*]
    };
}

/// The bit test, bit scan and count rows.
pub(super) const BITS: &[Form] = wide_rows! {
    "bt" [] 0xa3 0xc8;
    "bts" [] 0xab 0xc8;
    "btr" [] 0xb3 0xc8;
    "btc" [] 0xbb 0xc8;
    "bsf" [] 0xbc 0xc1;
    "bsr" [] 0xbd 0xc1;
    "popcnt" [0xf3] 0xb8 0xc1;
    "lzcnt" [0xf3] 0xbd 0xc1;
    "tzcnt" [0xf3] 0xbc 0xc1;
};

/// Four register forms of one exchange row with `ModRM` `c8` or `d1`.
macro_rules! xchg_rows {
    ($($row:literal $n8:literal $n16:literal $n32:literal $n64:literal [$($o8:literal),+] [$($o:literal),+] [$($r:ident),*]
        $rule8:expr, $rule16:expr, $rule32:expr, $rule64:expr;)*) => {
        &[$(
            form!("single", $row, 8, concat!($row, " ", $n8), Plain, [] [$($o8),+] [], [$($r),*], [], 0, 64, $rule8),
            form!("single", $row, 16, concat!($row, " ", $n16), Plain, [] [0x66, $($o),+] [], [$($r),*], [], 0, 64, $rule16),
            form!("single", $row, 32, concat!($row, " ", $n32), Plain, [] [$($o),+] [], [$($r),*], [], 0, 64, $rule32),
            form!("single", $row, 64, concat!($row, " ", $n64), Plain, [] [0x48, $($o),+] [], [$($r),*], [], 0, 64, $rule64),
        )*]
    };
}

/// The exchange rows.
pub(super) const EXCHANGE: &[Form] = xchg_rows! {
    "xchg" "al, cl" "ax, cx" "eax, ecx" "rax, rcx" [0x86, 0xc8] [0x87, 0xc8] [Rax, Rcx, Flags] Rule::Free, Rule::Free, Rule::Free, Rule::Free;
    "xadd" "al, cl" "ax, cx" "eax, ecx" "rax, rcx" [0x0f, 0xc0, 0xc8] [0x0f, 0xc1, 0xc8] [Rax, Rcx, Flags] Rule::Free, Rule::Free, Rule::Free, Rule::Free;
    "cmpxchg" "cl, dl" "cx, dx" "ecx, edx" "rcx, rdx" [0x0f, 0xb0, 0xd1] [0x0f, 0xb1, 0xd1] [Rax, Rcx, Rdx, Flags]
        Rule::Equal(8), Rule::Equal(16), Rule::Equal(32), Rule::Equal(64);
};

/// The other single forms.
pub(super) const SINGLE: &[Form] = &[
    form!("single", "xchg", 32, "xchg dword ptr [rsi], ecx", Plain, [] [0x87, 0x0e] [],
        [Rsi, Rcx, Flags], [Rsi = 8], 32, 16, Rule::Free),
    plain!(
        "single",
        "xchg",
        32,
        "xchg ecx, eax",
        [0x91],
        [Rax, Rcx, Flags],
        16
    ),
    plain!(
        "single",
        "xchg",
        32,
        "xchg eax, eax",
        [0x87, 0xc0],
        [Rax, Flags],
        16
    ),
    plain!(
        "single",
        "xchg",
        16,
        "xchg ax, ax",
        [0x66, 0x90],
        [Rax, Flags],
        16
    ),
    plain!(
        "single",
        "bswap",
        32,
        "bswap eax",
        [0x0f, 0xc8],
        [Rax, Flags],
        64
    ),
    plain!(
        "single",
        "bswap",
        64,
        "bswap rax",
        [0x48, 0x0f, 0xc8],
        [Rax, Flags],
        64
    ),
    plain!(
        "single",
        "bt",
        32,
        "bt eax, 0x5",
        [0x0f, 0xba, 0xe0, 0x05],
        [Rax, Flags],
        16
    ),
    plain!(
        "single",
        "btr",
        32,
        "btr eax, 0x1f",
        [0x0f, 0xba, 0xf0, 0x1f],
        [Rax, Flags],
        16
    ),
    plain!(
        "single",
        "btc",
        64,
        "btc rax, 0x3f",
        [0x48, 0x0f, 0xba, 0xf8, 0x3f],
        [Rax, Flags],
        16
    ),
    form!("single", "bt", 32, "bt dword ptr [rsi], ecx", Plain, [] [0x0f, 0xa3, 0x0e] [],
        [Rsi, Rcx, Flags], [Rsi = 16], 64, 16, Rule::BitIndex),
    form!("single", "bts", 32, "bts dword ptr [rsi], ecx", Plain, [] [0x0f, 0xab, 0x0e] [],
        [Rsi, Rcx, Flags], [Rsi = 16], 64, 16, Rule::BitIndex),
    plain!("single", "cbw", 16, "cbw", [0x66, 0x98], [Rax, Flags], 64),
    plain!("single", "cwde", 32, "cwde", [0x98], [Rax, Flags], 64),
    plain!("single", "cdqe", 64, "cdqe", [0x48, 0x98], [Rax, Flags], 64),
    plain!(
        "single",
        "cwd",
        16,
        "cwd",
        [0x66, 0x99],
        [Rax, Rdx, Flags],
        64
    ),
    plain!("single", "cdq", 32, "cdq", [0x99], [Rax, Rdx, Flags], 64),
    plain!(
        "single",
        "cqo",
        64,
        "cqo",
        [0x48, 0x99],
        [Rax, Rdx, Flags],
        64
    ),
    plain!("single", "lahf", 8, "lahf", [0x9f], [Rax, Flags], 64),
    plain!("single", "sahf", 8, "sahf", [0x9e], [Rax, Flags], 64),
    plain!("single", "cmc", 16, "cmc", [0xf5], [Flags], 64),
    plain!("single", "clc", 16, "clc", [0xf8], [Flags], 64),
    plain!("single", "stc", 16, "stc", [0xf9], [Flags], 64),
    plain!("single", "cld", 16, "cld", [0xfc], [Flags], 64),
    plain!(
        "single",
        "endbr64",
        64,
        "endbr64",
        [0xf3, 0x0f, 0x1e, 0xfa],
        [Rax, Rcx, Flags],
        64
    ),
    plain!("single", "nop", 64, "nop", [0x90], [Rax, Rcx, Flags], 64),
    plain!(
        "single",
        "nop",
        64,
        "nop dword ptr [rax]",
        [0x0f, 0x1f, 0x00],
        [Rax, Flags],
        16
    ),
    plain!(
        "single",
        "nop",
        64,
        "nop word ptr [rax+rax*1+0x0]",
        [0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        [Rax, Flags],
        16
    ),
    plain!(
        "single",
        "pause",
        64,
        "pause",
        [0xf3, 0x90],
        [Rax, Flags],
        64
    ),
];
