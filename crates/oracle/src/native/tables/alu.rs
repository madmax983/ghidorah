//! The forms of the `alu2`, `alu1`, `shift` and `muldiv` vector files.

use crate::native::{Form, R, Rule};

/// Four register forms of one `op r/m, r` row: `al, cl` to `rax, rcx`.
macro_rules! alu2_rows {
    ($($row:literal $o8:literal $o:literal;)*) => {
        &[$(
            plain!("alu2", $row, 8, concat!($row, " al, cl"), [$o8, 0xc8], [Rax, Rcx, Flags], 64),
            plain!("alu2", $row, 16, concat!($row, " ax, cx"), [0x66, $o, 0xc8], [Rax, Rcx, Flags], 64),
            plain!("alu2", $row, 32, concat!($row, " eax, ecx"), [$o, 0xc8], [Rax, Rcx, Flags], 64),
            plain!("alu2", $row, 64, concat!($row, " rax, rcx"), [0x48, $o, 0xc8], [Rax, Rcx, Flags], 64),
        )*]
    };
}

/// The `alu2` rows and their operand forms.
pub(super) const ALU2: &[Form] = &[
    plain!(
        "alu2",
        "add",
        8,
        "add ah, cl",
        [0x00, 0xcc],
        [Rax, Rcx, Flags],
        16
    ),
    form!("alu2", "add", 32, "add dword ptr [rsi], ecx", Plain, [] [0x01, 0x0e] [],
        [Rsi, Rcx, Flags], [Rsi = 8], 32, 16, Rule::Free),
    form!("alu2", "sub", 32, "sub ecx, dword ptr [rsi]", Plain, [] [0x2b, 0x0e] [],
        [Rcx, Rsi, Flags], [Rsi = 8], 32, 16, Rule::Free),
    plain!(
        "alu2",
        "add",
        32,
        "add eax, -0x10",
        [0x83, 0xc0, 0xf0],
        [Rax, Flags],
        16
    ),
    plain!(
        "alu2",
        "and",
        64,
        "and rax, -0x6dcba988",
        [0x48, 0x25, 0x78, 0x56, 0x34, 0x92],
        [Rax, Flags],
        16
    ),
    plain!(
        "alu2",
        "xor",
        32,
        "xor eax, eax",
        [0x31, 0xc0],
        [Rax, Flags],
        16
    ),
    form!("alu2", "cmp", 8, "cmp byte ptr [rsi+rdi*2+8], 0x7f", Plain,
        [] [0x80, 0x7c, 0x7e, 0x08, 0x7f] [], [Rsi, Rdi, Flags], [Rsi = 0], 32, 16,
        Rule::Small(R::Rdi, 8)),
    plain!(
        "alu2",
        "test",
        32,
        "test r9d, 0x10",
        [0x41, 0xf7, 0xc1, 0x10, 0x00, 0x00, 0x00],
        [R9, Flags],
        16
    ),
    plain!(
        "alu2",
        "adc",
        64,
        "adc r10, r11",
        [0x4d, 0x11, 0xda],
        [R10, R11, Flags],
        16
    ),
];

/// The register forms of each `alu2` row.
pub(super) const ALU2_ROWS: &[Form] = alu2_rows! {
    "add" 0x00 0x01;
    "or" 0x08 0x09;
    "adc" 0x10 0x11;
    "sbb" 0x18 0x19;
    "and" 0x20 0x21;
    "sub" 0x28 0x29;
    "xor" 0x30 0x31;
    "cmp" 0x38 0x39;
    "test" 0x84 0x85;
};

/// Four register forms of one group 3 or group 4 and 5 row with `rax` as the operand.
macro_rules! unary_rows {
    ($file:literal; $($row:literal $o8:literal $o:literal $m:literal;)*) => {
        &[$(
            plain!($file, $row, 8, concat!($row, " al"), [$o8, $m], [Rax, Flags], 64),
            plain!($file, $row, 16, concat!($row, " ax"), [0x66, $o, $m], [Rax, Flags], 64),
            plain!($file, $row, 32, concat!($row, " eax"), [$o, $m], [Rax, Flags], 64),
            plain!($file, $row, 64, concat!($row, " rax"), [0x48, $o, $m], [Rax, Flags], 64),
        )*]
    };
}

/// The `alu1` rows.
pub(super) const ALU1_ROWS: &[Form] = unary_rows! {
    "alu1";
    "inc" 0xfe 0xff 0xc0;
    "dec" 0xfe 0xff 0xc8;
    "not" 0xf6 0xf7 0xd0;
    "neg" 0xf6 0xf7 0xd8;
};

/// The operand forms of the `alu1` rows.
pub(super) const ALU1: &[Form] = &[
    form!("alu1", "inc", 32, "inc dword ptr [rsi]", Plain, [] [0xff, 0x06] [],
        [Rsi, Flags], [Rsi = 8], 32, 16, Rule::Free),
    plain!(
        "alu1",
        "neg",
        8,
        "neg sil",
        [0x40, 0xf6, 0xde],
        [Rsi, Flags],
        16
    ),
    plain!("alu1", "dec", 8, "dec bh", [0xfe, 0xcf], [Rbx, Flags], 16),
];

/// Four forms of one shift row with the count in `cl`.
macro_rules! shift_rows {
    ($($row:literal $m:literal;)*) => {
        &[$(
            plain!("shift", $row, 8, concat!($row, " al, cl"), [0xd2, $m], [Rax, Rcx, Flags], 64),
            plain!("shift", $row, 16, concat!($row, " ax, cl"), [0x66, 0xd3, $m], [Rax, Rcx, Flags], 64),
            plain!("shift", $row, 32, concat!($row, " eax, cl"), [0xd3, $m], [Rax, Rcx, Flags], 64),
            plain!("shift", $row, 64, concat!($row, " rax, cl"), [0x48, 0xd3, $m], [Rax, Rcx, Flags], 64),
            plain!("shift", $row, 32, concat!($row, " eax, 0x5"), [0xc1, $m, 0x05], [Rax, Flags], 16),
            plain!("shift", $row, 32, concat!($row, " eax, 0x1"), [0xd1, $m], [Rax, Flags], 16),
        )*]
    };
}

/// The forms of `shld` or `shrd` with the opcode of the `cl` form and of the immediate form.
macro_rules! double_rows {
    ($($row:literal $cl:literal $imm:literal;)*) => {
        &[$(
            form!("shift", $row, 16, concat!($row, " ax, cx, cl"), Plain, [] [0x66, 0x0f, $cl, 0xc8] [],
                [Rax, Rcx, Flags], [], 0, 64, Rule::Count16),
            plain!("shift", $row, 32, concat!($row, " eax, ecx, cl"), [0x0f, $cl, 0xc8], [Rax, Rcx, Flags], 64),
            plain!("shift", $row, 64, concat!($row, " rax, rcx, cl"), [0x48, 0x0f, $cl, 0xc8], [Rax, Rcx, Flags], 64),
            plain!("shift", $row, 32, concat!($row, " eax, ecx, 0x7"), [0x0f, $imm, 0xc8, 0x07], [Rax, Rcx, Flags], 16),
        )*]
    };
}

/// The `shift` rows.
pub(super) const SHIFT: &[Form] = shift_rows! {
    "shl" 0xe0;
    "shr" 0xe8;
    "sar" 0xf8;
    "rol" 0xc0;
    "ror" 0xc8;
};

/// The `shld` and `shrd` rows.
pub(super) const SHIFT_DOUBLE: &[Form] = double_rows! {
    "shld" 0xa5 0xa4;
    "shrd" 0xad 0xac;
};

/// Four forms of one multiply or divide row with `cl` to `rcx` as the operand.
macro_rules! muldiv_rows {
    ($($row:literal $m:literal $r8:expr, $r16:expr, $r32:expr, $r64:expr;)*) => {
        &[$(
            form!("muldiv", $row, 8, concat!($row, " cl"), Plain, [] [0xf6, $m] [],
                [Rax, Rcx, Rdx, Flags], [], 0, 64, $r8),
            form!("muldiv", $row, 16, concat!($row, " cx"), Plain, [] [0x66, 0xf7, $m] [],
                [Rax, Rcx, Rdx, Flags], [], 0, 64, $r16),
            form!("muldiv", $row, 32, concat!($row, " ecx"), Plain, [] [0xf7, $m] [],
                [Rax, Rcx, Rdx, Flags], [], 0, 64, $r32),
            form!("muldiv", $row, 64, concat!($row, " rcx"), Plain, [] [0x48, 0xf7, $m] [],
                [Rax, Rcx, Rdx, Flags], [], 0, 64, $r64),
        )*]
    };
}

/// The `muldiv` rows with one operand.
pub(super) const MULDIV_ROWS: &[Form] = muldiv_rows! {
    "mul" 0xe1 Rule::Free, Rule::Free, Rule::Free, Rule::Free;
    "imul" 0xe9 Rule::Free, Rule::Free, Rule::Free, Rule::Free;
    "div" 0xf1 Rule::Div(8), Rule::Div(16), Rule::Div(32), Rule::Div(64);
    "idiv" 0xf9 Rule::Idiv(8), Rule::Idiv(16), Rule::Idiv(32), Rule::Idiv(64);
};

/// The `imul` forms with two and three operands.
pub(super) const MULDIV: &[Form] = &[
    plain!(
        "muldiv",
        "imul",
        32,
        "imul eax, ecx",
        [0x0f, 0xaf, 0xc1],
        [Rax, Rcx, Rdx, Flags],
        16
    ),
    plain!(
        "muldiv",
        "imul",
        16,
        "imul ax, cx",
        [0x66, 0x0f, 0xaf, 0xc1],
        [Rax, Rcx, Rdx, Flags],
        16
    ),
    plain!(
        "muldiv",
        "imul",
        64,
        "imul rax, rcx",
        [0x48, 0x0f, 0xaf, 0xc1],
        [Rax, Rcx, Rdx, Flags],
        16
    ),
    plain!(
        "muldiv",
        "imul",
        32,
        "imul eax, ecx, 0x7",
        [0x6b, 0xc1, 0x07],
        [Rax, Rcx, Rdx, Flags],
        16
    ),
    plain!(
        "muldiv",
        "imul",
        64,
        "imul rax, rcx, -0x12345678",
        [0x48, 0x69, 0xc1, 0x88, 0xa9, 0xcb, 0xed],
        [Rax, Rcx, Rdx, Flags],
        16
    ),
];
