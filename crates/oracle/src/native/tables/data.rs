//! The forms of the `mov`, `movx`, `lea`, `cmov`, `setcc`, `stack` and `string` vector files.

use crate::native::{Form, Rule};

/// The `mov` and `movabs` rows.
pub(super) const MOV: &[Form] = &[
    plain!(
        "mov",
        "mov",
        8,
        "mov al, cl",
        [0x88, 0xc8],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "mov",
        "mov",
        16,
        "mov ax, cx",
        [0x66, 0x89, 0xc8],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "mov",
        "mov",
        32,
        "mov eax, ecx",
        [0x89, 0xc8],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "mov",
        "mov",
        64,
        "mov rax, rcx",
        [0x48, 0x89, 0xc8],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "mov",
        "mov",
        8,
        "mov ah, cl",
        [0x88, 0xcc],
        [Rax, Rcx, Flags],
        16
    ),
    plain!(
        "mov",
        "mov",
        8,
        "mov sil, cl",
        [0x40, 0x88, 0xce],
        [Rsi, Rcx, Flags],
        16
    ),
    plain!(
        "mov",
        "mov",
        32,
        "mov eax, 0x89abcdef",
        [0xb8, 0xef, 0xcd, 0xab, 0x89],
        [Rax, Flags],
        16
    ),
    plain!(
        "mov",
        "mov",
        64,
        "mov rax, -0x2",
        [0x48, 0xc7, 0xc0, 0xfe, 0xff, 0xff, 0xff],
        [Rax, Flags],
        16
    ),
    form!("mov", "mov", 64, "mov rax, qword ptr [rsi+0x8]", Plain, [] [0x48, 0x8b, 0x46, 0x08] [],
        [Rax, Rsi, Flags], [Rsi = 0], 32, 16, Rule::Free),
    form!("mov", "mov", 64, "mov qword ptr [rsi+0x8], rcx", Plain, [] [0x48, 0x89, 0x4e, 0x08] [],
        [Rcx, Rsi, Flags], [Rsi = 0], 32, 16, Rule::Free),
    form!("mov", "mov", 8, "mov byte ptr [rsi], cl", Plain, [] [0x88, 0x0e] [],
        [Rcx, Rsi, Flags], [Rsi = 8], 32, 16, Rule::Free),
    form!("mov", "mov", 16, "mov cx, word ptr [rsi]", Plain, [] [0x66, 0x8b, 0x0e] [],
        [Rcx, Rsi, Flags], [Rsi = 8], 32, 16, Rule::Free),
    plain!(
        "mov",
        "movabs",
        64,
        "movabs rax, 0x1122334455667788",
        [0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        [Rax, Flags],
        64
    ),
];

/// The `movzx`, `movsx` and `movsxd` rows.
pub(super) const MOVX: &[Form] = &[
    plain!(
        "movx",
        "movzx",
        16,
        "movzx ax, cl",
        [0x66, 0x0f, 0xb6, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "movx",
        "movzx",
        32,
        "movzx eax, cl",
        [0x0f, 0xb6, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "movx",
        "movzx",
        32,
        "movzx eax, cx",
        [0x0f, 0xb7, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "movx",
        "movzx",
        64,
        "movzx rax, cl",
        [0x48, 0x0f, 0xb6, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "movx",
        "movzx",
        64,
        "movzx rax, cx",
        [0x48, 0x0f, 0xb7, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "movx",
        "movzx",
        32,
        "movzx eax, ch",
        [0x0f, 0xb6, 0xc5],
        [Rax, Rcx, Flags],
        16
    ),
    plain!(
        "movx",
        "movsx",
        16,
        "movsx ax, cl",
        [0x66, 0x0f, 0xbe, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "movx",
        "movsx",
        32,
        "movsx eax, cl",
        [0x0f, 0xbe, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "movx",
        "movsx",
        32,
        "movsx eax, cx",
        [0x0f, 0xbf, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "movx",
        "movsx",
        64,
        "movsx rax, cl",
        [0x48, 0x0f, 0xbe, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    plain!(
        "movx",
        "movsx",
        64,
        "movsx rax, cx",
        [0x48, 0x0f, 0xbf, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
    form!("movx", "movsx", 32, "movsx eax, byte ptr [rsi]", Plain, [] [0x0f, 0xbe, 0x06] [],
        [Rax, Rsi, Flags], [Rsi = 8], 32, 16, Rule::Free),
    plain!(
        "movx",
        "movsxd",
        64,
        "movsxd rax, ecx",
        [0x48, 0x63, 0xc1],
        [Rax, Rcx, Flags],
        64
    ),
];

/// The `lea` row.
pub(super) const LEA: &[Form] = &[
    plain!(
        "lea",
        "lea",
        16,
        "lea ax, [rsi+rcx*2+0x8]",
        [0x66, 0x8d, 0x44, 0x4e, 0x08],
        [Rax, Rsi, Rcx, Flags],
        64
    ),
    plain!(
        "lea",
        "lea",
        32,
        "lea eax, [rsi+rcx*2+0x8]",
        [0x8d, 0x44, 0x4e, 0x08],
        [Rax, Rsi, Rcx, Flags],
        64
    ),
    plain!(
        "lea",
        "lea",
        64,
        "lea rax, [rsi+rcx*2+0x8]",
        [0x48, 0x8d, 0x44, 0x4e, 0x08],
        [Rax, Rsi, Rcx, Flags],
        64
    ),
    plain!(
        "lea",
        "lea",
        32,
        "lea eax, [esi+ecx*2+0x8]",
        [0x67, 0x8d, 0x44, 0x4e, 0x08],
        [Rax, Rsi, Rcx, Flags],
        16
    ),
    plain!(
        "lea",
        "lea",
        64,
        "lea rax, [rcx*8-0x13]",
        [0x48, 0x8d, 0x04, 0xcd, 0xed, 0xff, 0xff, 0xff],
        [Rax, Rcx, Flags],
        16
    ),
];

/// Three forms of one `cmovcc` row: 16, 32 and 64 bits.
macro_rules! cmov_rows {
    ($($row:literal $o:literal;)*) => {
        &[$(
            plain!("cmov", $row, 16, concat!($row, " ax, cx"), [0x66, 0x0f, $o, 0xc1], [Rax, Rcx, Flags], 64),
            plain!("cmov", $row, 32, concat!($row, " eax, ecx"), [0x0f, $o, 0xc1], [Rax, Rcx, Flags], 64),
            plain!("cmov", $row, 64, concat!($row, " rax, rcx"), [0x48, 0x0f, $o, 0xc1], [Rax, Rcx, Flags], 64),
        )*]
    };
}

/// The `cmovcc` rows.
pub(super) const CMOV: &[Form] = cmov_rows! {
    "cmovo" 0x40; "cmovno" 0x41; "cmovb" 0x42; "cmovae" 0x43;
    "cmove" 0x44; "cmovne" 0x45; "cmovbe" 0x46; "cmova" 0x47;
    "cmovs" 0x48; "cmovns" 0x49; "cmovp" 0x4a; "cmovnp" 0x4b;
    "cmovl" 0x4c; "cmovge" 0x4d; "cmovle" 0x4e; "cmovg" 0x4f;
};

/// One `setcc al` form for each row.
macro_rules! setcc_rows {
    ($($row:literal $o:literal;)*) => {
        &[$(
            plain!("setcc", $row, 8, concat!($row, " al"), [0x0f, $o, 0xc0], [Rax, Flags], 64),
        )*]
    };
}

/// The `setcc` rows.
pub(super) const SETCC: &[Form] = setcc_rows! {
    "seto" 0x90; "setno" 0x91; "setb" 0x92; "setae" 0x93;
    "sete" 0x94; "setne" 0x95; "setbe" 0x96; "seta" 0x97;
    "sets" 0x98; "setns" 0x99; "setp" 0x9a; "setnp" 0x9b;
    "setl" 0x9c; "setge" 0x9d; "setle" 0x9e; "setg" 0x9f;
};

/// The operand forms of the `setcc` rows.
pub(super) const SETCC_MORE: &[Form] = &[
    plain!(
        "setcc",
        "sete",
        8,
        "sete ah",
        [0x0f, 0x94, 0xc4],
        [Rax, Flags],
        16
    ),
    form!("setcc", "setne", 8, "setne byte ptr [rsi]", Plain, [] [0x0f, 0x95, 0x06] [],
        [Rsi, Flags], [Rsi = 8], 32, 16, Rule::Free),
];

/// The `stack` rows.
pub(super) const STACK: &[Form] = &[
    form!("stack", "push", 64, "push rax", Plain, [] [0x50] [],
        [Rax, Rsp, Flags], [Rsp = 32], 64, 64, Rule::Free),
    form!("stack", "push", 64, "push r12", Plain, [] [0x41, 0x54] [],
        [R12, Rsp, Flags], [Rsp = 32], 64, 16, Rule::Free),
    form!("stack", "push", 64, "push -0x10", Plain, [] [0x6a, 0xf0] [],
        [Rsp, Flags], [Rsp = 32], 64, 16, Rule::Free),
    form!("stack", "push", 64, "push 0x12345678", Plain, [] [0x68, 0x78, 0x56, 0x34, 0x12] [],
        [Rsp, Flags], [Rsp = 32], 64, 16, Rule::Free),
    form!("stack", "push", 64, "push qword ptr [rsi]", Plain, [] [0xff, 0x36] [],
        [Rsi, Rsp, Flags], [Rsi = 0, Rsp = 48], 64, 16, Rule::Free),
    form!("stack", "push", 16, "push ax", Plain, [] [0x66, 0x50] [],
        [Rax, Rsp, Flags], [Rsp = 32], 64, 64, Rule::Free),
    form!("stack", "pop", 64, "pop rax", Plain, [] [0x58] [],
        [Rax, Rsp, Flags], [Rsp = 32], 64, 64, Rule::Free),
    form!("stack", "pop", 64, "pop r13", Plain, [] [0x41, 0x5d] [],
        [R13, Rsp, Flags], [Rsp = 32], 64, 16, Rule::Free),
    form!("stack", "pop", 64, "pop qword ptr [rsi]", Plain, [] [0x8f, 0x06] [],
        [Rsi, Rsp, Flags], [Rsi = 0, Rsp = 32], 64, 16, Rule::Free),
    form!("stack", "pop", 16, "pop ax", Plain, [] [0x66, 0x58] [],
        [Rax, Rsp, Flags], [Rsp = 32], 64, 64, Rule::Free),
    form!("stack", "leave", 64, "leave", Plain, [] [0xc9] [],
        [Rsp, Rbp, Flags], [Rbp = 16, Rsp = 48], 64, 64, Rule::Free),
    form!("stack", "pushf", 64, "pushf", Plain, [] [0x9c] [],
        [Rsp, Flags], [Rsp = 32], 64, 64, Rule::Free),
    form!("stack", "popf", 64, "popf", Plain, [] [0x9d] [],
        [Rsp, Flags], [Rsp = 32], 64, 64, Rule::PopfWord),
];

/// The `string` rows. `rsi` points to byte 0 and `rdi` to byte 32 of the buffer.
pub(super) const STRING: &[Form] = &[
    form!("string", "movs", 8, "movs byte", Plain, [] [0xa4] [],
        [Rsi, Rdi, Rcx, Flags], [Rsi = 0, Rdi = 32], 64, 64, Rule::Free),
    form!("string", "movs", 32, "movs dword", Plain, [] [0xa5] [],
        [Rsi, Rdi, Rcx, Flags], [Rsi = 0, Rdi = 32], 64, 64, Rule::Free),
    form!("string", "movs", 64, "movs qword", Plain, [] [0x48, 0xa5] [],
        [Rsi, Rdi, Rcx, Flags], [Rsi = 0, Rdi = 32], 64, 64, Rule::Free),
    form!("string", "movs", 8, "rep movs byte", Plain, [] [0xf3, 0xa4] [],
        [Rsi, Rdi, Rcx, Flags], [Rsi = 0, Rdi = 32], 64, 16, Rule::SmallRcx(9)),
    form!("string", "movs", 64, "rep movs qword", Plain, [] [0xf3, 0x48, 0xa5] [],
        [Rsi, Rdi, Rcx, Flags], [Rsi = 0, Rdi = 32], 64, 16, Rule::SmallRcx(4)),
    form!("string", "stos", 8, "stos byte", Plain, [] [0xaa] [],
        [Rax, Rdi, Rcx, Flags], [Rdi = 32], 64, 64, Rule::Free),
    form!("string", "stos", 64, "stos qword", Plain, [] [0x48, 0xab] [],
        [Rax, Rdi, Rcx, Flags], [Rdi = 32], 64, 64, Rule::Free),
    form!("string", "stos", 64, "rep stos qword", Plain, [] [0xf3, 0x48, 0xab] [],
        [Rax, Rdi, Rcx, Flags], [Rdi = 32], 64, 16, Rule::SmallRcx(4)),
    form!("string", "lods", 8, "lods byte", Plain, [] [0xac] [],
        [Rax, Rsi, Rcx, Flags], [Rsi = 0], 64, 64, Rule::Free),
    form!("string", "lods", 64, "lods qword", Plain, [] [0x48, 0xad] [],
        [Rax, Rsi, Rcx, Flags], [Rsi = 0], 64, 64, Rule::Free),
    form!("string", "scas", 8, "scas byte", Plain, [] [0xae] [],
        [Rax, Rdi, Rcx, Flags], [Rdi = 32], 64, 64, Rule::Free),
    form!("string", "scas", 64, "scas qword", Plain, [] [0x48, 0xaf] [],
        [Rax, Rdi, Rcx, Flags], [Rdi = 32], 64, 64, Rule::Free),
    form!("string", "scas", 8, "repne scas byte", Plain, [] [0xf2, 0xae] [],
        [Rax, Rdi, Rcx, Flags], [Rdi = 32], 64, 16, Rule::SmallRcx(17)),
    form!("string", "cmps", 8, "cmps byte", Plain, [] [0xa6] [],
        [Rsi, Rdi, Rcx, Flags], [Rsi = 0, Rdi = 32], 64, 64, Rule::Free),
    form!("string", "cmps", 64, "cmps qword", Plain, [] [0x48, 0xa7] [],
        [Rsi, Rdi, Rcx, Flags], [Rsi = 0, Rdi = 32], 64, 64, Rule::Free),
    form!("string", "cmps", 8, "repe cmps byte", Plain, [] [0xf3, 0xa6] [],
        [Rsi, Rdi, Rcx, Flags], [Rsi = 0, Rdi = 32], 64, 16, Rule::SameMem),
];
