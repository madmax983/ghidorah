//! The forms of the `sse_move` and `sse_zero` vector files.
//!
//! A memory form points `rsi` at byte 16 of the buffer, so an aligned move finds a 16-byte
//! boundary.

use crate::native::{Form, Rule};

/// The register move, the load and the store of one full-width move row.
macro_rules! move_rows {
    ($($row:literal [$($rr:literal),+] [$($ld:literal),+] [$($st:literal),+];)*) => {
        &[$(
            plain!("sse_move", $row, 128, concat!($row, " xmm0, xmm1"), [$($rr),+], [Xmm0, Xmm1, Flags], 64),
            form!("sse_move", $row, 128, concat!($row, " xmm0, xmmword ptr [rsi]"), Plain, [] [$($ld),+] [],
                [Xmm0, Rsi, Flags], [Rsi = 16], 64, 32, Rule::Free),
            form!("sse_move", $row, 128, concat!($row, " xmmword ptr [rsi], xmm1"), Plain, [] [$($st),+] [],
                [Xmm1, Rsi, Flags], [Rsi = 16], 64, 32, Rule::Free),
        )*]
    };
}

/// The full-width move rows.
pub(super) const SSE_MOVE_FULL: &[Form] = move_rows! {
    "movaps" [0x0f, 0x28, 0xc1] [0x0f, 0x28, 0x06] [0x0f, 0x29, 0x0e];
    "movups" [0x0f, 0x10, 0xc1] [0x0f, 0x10, 0x06] [0x0f, 0x11, 0x0e];
    "movapd" [0x66, 0x0f, 0x28, 0xc1] [0x66, 0x0f, 0x28, 0x06] [0x66, 0x0f, 0x29, 0x0e];
    "movupd" [0x66, 0x0f, 0x10, 0xc1] [0x66, 0x0f, 0x10, 0x06] [0x66, 0x0f, 0x11, 0x0e];
    "movdqa" [0x66, 0x0f, 0x6f, 0xc1] [0x66, 0x0f, 0x6f, 0x06] [0x66, 0x0f, 0x7f, 0x0e];
    "movdqu" [0xf3, 0x0f, 0x6f, 0xc1] [0xf3, 0x0f, 0x6f, 0x06] [0xf3, 0x0f, 0x7f, 0x0e];
};

/// The scalar and the general-register move rows.
pub(super) const SSE_MOVE: &[Form] = &[
    plain!(
        "sse_move",
        "movd",
        32,
        "movd xmm0, ecx",
        [0x66, 0x0f, 0x6e, 0xc1],
        [Xmm0, Rcx, Flags],
        64
    ),
    plain!(
        "sse_move",
        "movd",
        32,
        "movd ecx, xmm0",
        [0x66, 0x0f, 0x7e, 0xc1],
        [Rcx, Xmm0, Flags],
        64
    ),
    form!("sse_move", "movd", 32, "movd xmm0, dword ptr [rsi]", Plain, [] [0x66, 0x0f, 0x6e, 0x06] [],
        [Xmm0, Rsi, Flags], [Rsi = 16], 64, 16, Rule::Free),
    plain!(
        "sse_move",
        "movq",
        64,
        "movq xmm0, rcx",
        [0x66, 0x48, 0x0f, 0x6e, 0xc1],
        [Xmm0, Rcx, Flags],
        64
    ),
    plain!(
        "sse_move",
        "movq",
        64,
        "movq rcx, xmm0",
        [0x66, 0x48, 0x0f, 0x7e, 0xc1],
        [Rcx, Xmm0, Flags],
        64
    ),
    plain!(
        "sse_move",
        "movq",
        64,
        "movq xmm0, xmm1",
        [0xf3, 0x0f, 0x7e, 0xc1],
        [Xmm0, Xmm1, Flags],
        64
    ),
    form!("sse_move", "movq", 64, "movq xmm0, qword ptr [rsi]", Plain, [] [0xf3, 0x0f, 0x7e, 0x06] [],
        [Xmm0, Rsi, Flags], [Rsi = 16], 64, 16, Rule::Free),
    form!("sse_move", "movq", 64, "movq qword ptr [rsi], xmm1", Plain, [] [0x66, 0x0f, 0xd6, 0x0e] [],
        [Xmm1, Rsi, Flags], [Rsi = 16], 64, 16, Rule::Free),
    plain!(
        "sse_move",
        "movss",
        32,
        "movss xmm0, xmm1",
        [0xf3, 0x0f, 0x10, 0xc1],
        [Xmm0, Xmm1, Flags],
        64
    ),
    form!("sse_move", "movss", 32, "movss xmm0, dword ptr [rsi]", Plain, [] [0xf3, 0x0f, 0x10, 0x06] [],
        [Xmm0, Rsi, Flags], [Rsi = 16], 64, 32, Rule::Free),
    form!("sse_move", "movss", 32, "movss dword ptr [rsi], xmm1", Plain, [] [0xf3, 0x0f, 0x11, 0x0e] [],
        [Xmm1, Rsi, Flags], [Rsi = 16], 64, 32, Rule::Free),
    plain!(
        "sse_move",
        "movsd",
        64,
        "movsd xmm0, xmm1",
        [0xf2, 0x0f, 0x10, 0xc1],
        [Xmm0, Xmm1, Flags],
        64
    ),
    form!("sse_move", "movsd", 64, "movsd xmm0, qword ptr [rsi]", Plain, [] [0xf2, 0x0f, 0x10, 0x06] [],
        [Xmm0, Rsi, Flags], [Rsi = 16], 64, 32, Rule::Free),
    form!("sse_move", "movsd", 64, "movsd qword ptr [rsi], xmm1", Plain, [] [0xf2, 0x0f, 0x11, 0x0e] [],
        [Xmm1, Rsi, Flags], [Rsi = 16], 64, 32, Rule::Free),
];

/// The `sse_zero` rows.
pub(super) const SSE_ZERO: &[Form] = &[
    plain!(
        "sse_zero",
        "pxor",
        128,
        "pxor xmm0, xmm0",
        [0x66, 0x0f, 0xef, 0xc0],
        [Xmm0, Flags],
        64
    ),
    plain!(
        "sse_zero",
        "pxor",
        128,
        "pxor xmm1, xmm1",
        [0x66, 0x0f, 0xef, 0xc9],
        [Xmm1, Flags],
        16
    ),
    plain!(
        "sse_zero",
        "xorps",
        128,
        "xorps xmm0, xmm0",
        [0x0f, 0x57, 0xc0],
        [Xmm0, Flags],
        64
    ),
    plain!(
        "sse_zero",
        "xorpd",
        128,
        "xorpd xmm0, xmm0",
        [0x66, 0x0f, 0x57, 0xc0],
        [Xmm0, Flags],
        64
    ),
];
