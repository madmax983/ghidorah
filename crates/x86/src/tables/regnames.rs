//! The register names.

use crate::regs::RegClass;

const GPR64: [&str; 32] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26",
    "r27", "r28", "r29", "r30", "r31",
];

const GPR32: [&str; 32] = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d",
    "r13d", "r14d", "r15d", "r16d", "r17d", "r18d", "r19d", "r20d", "r21d", "r22d", "r23d", "r24d",
    "r25d", "r26d", "r27d", "r28d", "r29d", "r30d", "r31d",
];

const GPR16: [&str; 32] = [
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
    "r14w", "r15w", "r16w", "r17w", "r18w", "r19w", "r20w", "r21w", "r22w", "r23w", "r24w", "r25w",
    "r26w", "r27w", "r28w", "r29w", "r30w", "r31w",
];

const GPR8: [&str; 32] = [
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b",
    "r13b", "r14b", "r15b", "r16b", "r17b", "r18b", "r19b", "r20b", "r21b", "r22b", "r23b", "r24b",
    "r25b", "r26b", "r27b", "r28b", "r29b", "r30b", "r31b",
];

const HIGH8: [&str; 4] = ["ah", "ch", "dh", "bh"];

const XMM: [&str; 32] = [
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
    "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17", "xmm18", "xmm19", "xmm20",
    "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30",
    "xmm31",
];

const YMM: [&str; 32] = [
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10",
    "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "ymm16", "ymm17", "ymm18", "ymm19", "ymm20",
    "ymm21", "ymm22", "ymm23", "ymm24", "ymm25", "ymm26", "ymm27", "ymm28", "ymm29", "ymm30",
    "ymm31",
];

const ZMM: [&str; 32] = [
    "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10",
    "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18", "zmm19", "zmm20",
    "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30",
    "zmm31",
];

const SEG: [&str; 8] = ["es", "cs", "ss", "ds", "fs", "gs", "?", "?"];
const MMX: [&str; 8] = ["mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"];
const ST: [&str; 8] = [
    "st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)",
];
const CR: [&str; 16] = [
    "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7", "cr8", "cr9", "cr10", "cr11", "cr12",
    "cr13", "cr14", "cr15",
];
const DR: [&str; 16] = [
    "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7", "dr8", "dr9", "dr10", "dr11", "dr12",
    "dr13", "dr14", "dr15",
];
const MASK: [&str; 8] = ["k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"];
const BND: [&str; 8] = ["bnd0", "bnd1", "bnd2", "bnd3", "?", "?", "?", "?"];

/// Gives the name of a register. An unknown field value gives `?`.
pub(crate) fn name(class: RegClass, number: u8, width_bits: u16, high: bool) -> &'static str {
    let n = usize::from(number);
    let table: &[&'static str] = match class {
        RegClass::Gpr if high => &HIGH8,
        RegClass::Gpr => match width_bits {
            8 => &GPR8,
            16 => &GPR16,
            32 => &GPR32,
            _ => &GPR64,
        },
        RegClass::Xmm => &XMM,
        RegClass::Ymm => &YMM,
        RegClass::Zmm => &ZMM,
        RegClass::Seg => &SEG,
        RegClass::Mmx => &MMX,
        RegClass::X87 => &ST,
        RegClass::Ctrl => &CR,
        RegClass::Debug => &DR,
        RegClass::Mask => &MASK,
        RegClass::Bnd => &BND,
        RegClass::Ip => return if width_bits == 32 { "eip" } else { "rip" },
    };
    table.get(n).copied().unwrap_or("?")
}
