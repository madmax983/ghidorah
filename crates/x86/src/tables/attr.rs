//! Layer 1 attributes of the one-byte map and the `0F` map (Intel SDM, volume 2,
//! appendix A).
//!
//! Each byte holds an immediate kind in bits 0 to 3 and three flags.

/// No immediate.
pub(crate) const I_NONE: u8 = 0;
/// One immediate byte.
pub(crate) const I_B: u8 = 1;
/// A 16-bit immediate.
pub(crate) const I_W: u8 = 2;
/// A 16-bit immediate with the `66` prefix, else a 32-bit immediate.
pub(crate) const I_Z: u8 = 3;
/// A 64-bit immediate with REX.W, a 16-bit immediate with `66`, else a 32-bit immediate.
pub(crate) const I_V: u8 = 4;
/// An 8-bit branch displacement.
pub(crate) const I_JB: u8 = 5;
/// A 16-bit branch displacement with `66`, else a 32-bit one (`jmp`, `jcc`).
pub(crate) const I_JZ: u8 = 6;
/// A 64-bit memory offset, or a 32-bit one with `67`.
pub(crate) const I_MOFFS: u8 = 7;
/// A 16-bit immediate and an 8-bit immediate (`enter`).
pub(crate) const I_WB: u8 = 8;
/// One immediate byte for the `ModRM` `reg` values 0 and 1 (`F6`).
pub(crate) const I_GRP3B: u8 = 9;
/// An `I_Z` immediate for the `ModRM` `reg` values 0 and 1 (`F7`).
pub(crate) const I_GRP3V: u8 = 10;
/// Two immediate bytes with the `66` or `F2` prefix (`0F 78`).
pub(crate) const I_BB: u8 = 11;
/// A 32-bit call displacement. The AMD rule takes 16 bits with `66`.
pub(crate) const I_JCALL: u8 = 12;

/// The opcode has a `ModRM` byte.
pub(crate) const MODRM: u8 = 1 << 4;
/// The opcode is not valid in the 64-bit mode.
pub(crate) const INV64: u8 = 1 << 5;
/// The opcode has no definition.
pub(crate) const UNDEF: u8 = 1 << 6;

const M: u8 = MODRM;

/// Rows `(first opcode, last opcode, attribute)` of the one-byte map.
const MAP0_ROWS: &[(u8, u8, u8)] = &[
    (0x00, 0x03, M),
    (0x04, 0x04, I_B),
    (0x05, 0x05, I_Z),
    (0x06, 0x07, INV64),
    (0x08, 0x0b, M),
    (0x0c, 0x0c, I_B),
    (0x0d, 0x0d, I_Z),
    (0x0e, 0x0e, INV64),
    (0x10, 0x13, M),
    (0x14, 0x14, I_B),
    (0x15, 0x15, I_Z),
    (0x16, 0x17, INV64),
    (0x18, 0x1b, M),
    (0x1c, 0x1c, I_B),
    (0x1d, 0x1d, I_Z),
    (0x1e, 0x1f, INV64),
    (0x20, 0x23, M),
    (0x24, 0x24, I_B),
    (0x25, 0x25, I_Z),
    (0x27, 0x27, INV64),
    (0x28, 0x2b, M),
    (0x2c, 0x2c, I_B),
    (0x2d, 0x2d, I_Z),
    (0x2f, 0x2f, INV64),
    (0x30, 0x33, M),
    (0x34, 0x34, I_B),
    (0x35, 0x35, I_Z),
    (0x37, 0x37, INV64),
    (0x38, 0x3b, M),
    (0x3c, 0x3c, I_B),
    (0x3d, 0x3d, I_Z),
    (0x3f, 0x3f, INV64),
    (0x60, 0x62, INV64),
    (0x63, 0x63, M),
    (0x68, 0x68, I_Z),
    (0x69, 0x69, M | I_Z),
    (0x6a, 0x6a, I_B),
    (0x6b, 0x6b, M | I_B),
    (0x70, 0x7f, I_JB),
    (0x80, 0x80, M | I_B),
    (0x81, 0x81, M | I_Z),
    (0x82, 0x82, INV64),
    (0x83, 0x83, M | I_B),
    (0x84, 0x8f, M),
    (0x9a, 0x9a, INV64),
    (0xa0, 0xa3, I_MOFFS),
    (0xa8, 0xa8, I_B),
    (0xa9, 0xa9, I_Z),
    (0xb0, 0xb7, I_B),
    (0xb8, 0xbf, I_V),
    (0xc0, 0xc1, M | I_B),
    (0xc2, 0xc2, I_W),
    (0xc4, 0xc5, INV64),
    (0xc6, 0xc6, M | I_B),
    (0xc7, 0xc7, M | I_Z),
    (0xc8, 0xc8, I_WB),
    (0xca, 0xca, I_W),
    (0xcd, 0xcd, I_B),
    (0xce, 0xce, INV64),
    (0xd0, 0xd3, M),
    (0xd4, 0xd6, INV64),
    (0xd8, 0xdf, M),
    (0xe0, 0xe3, I_JB),
    (0xe4, 0xe7, I_B),
    (0xe8, 0xe8, I_JCALL),
    (0xe9, 0xe9, I_JZ),
    (0xea, 0xea, INV64),
    (0xeb, 0xeb, I_JB),
    (0xf6, 0xf6, M | I_GRP3B),
    (0xf7, 0xf7, M | I_GRP3V),
    (0xfe, 0xff, M),
];

/// Rows of the `0F` map. Opcodes without a row have no `ModRM` and no immediate.
const MAP1_ROWS: &[(u8, u8, u8)] = &[
    (0x00, 0x03, M),
    (0x04, 0x04, UNDEF),
    (0x0a, 0x0a, UNDEF),
    (0x0c, 0x0c, UNDEF),
    (0x0d, 0x0d, M),
    (0x0f, 0x0f, M | I_B),
    (0x10, 0x23, M),
    (0x24, 0x27, UNDEF),
    (0x28, 0x2f, M),
    (0x36, 0x36, UNDEF),
    (0x39, 0x39, UNDEF),
    (0x3b, 0x3f, UNDEF),
    (0x40, 0x6f, M),
    (0x70, 0x73, M | I_B),
    (0x74, 0x76, M),
    (0x78, 0x78, M | I_BB),
    (0x79, 0x79, M),
    (0x7a, 0x7b, UNDEF),
    (0x7c, 0x7f, M),
    (0x80, 0x8f, I_JZ),
    (0x90, 0x9f, M),
    (0xa3, 0xa3, M),
    (0xa4, 0xa4, M | I_B),
    (0xa5, 0xa5, M),
    (0xa6, 0xa7, UNDEF),
    (0xab, 0xab, M),
    (0xac, 0xac, M | I_B),
    (0xad, 0xb9, M),
    (0xba, 0xba, M | I_B),
    (0xbb, 0xc1, M),
    (0xc2, 0xc2, M | I_B),
    (0xc3, 0xc3, M),
    (0xc4, 0xc6, M | I_B),
    (0xc7, 0xc7, M),
    (0xd0, 0xff, M),
];

/// Fills a table of 256 attributes from `(first, last, attribute)` rows.
macro_rules! ranges {
    ($rows:expr) => {{
        let rows: &[(u8, u8, u8)] = $rows;
        let mut table = [0; 256];
        let mut i = 0;
        while i < rows.len() {
            let (lo, hi, attr) = rows[i];
            let mut op = lo as usize;
            while op <= hi as usize {
                table[op] = attr;
                op += 1;
            }
            i += 1;
        }
        table
    }};
}

/// The attributes of the one-byte map.
pub(crate) const MAP0: [u8; 256] = ranges!(MAP0_ROWS);

/// The attributes of the `0F` map.
pub(crate) const MAP1: [u8; 256] = ranges!(MAP1_ROWS);

/// Gives the attribute of an opcode in the one-byte map or the `0F` map.
pub(crate) fn of(map1: bool, opcode: u8) -> u8 {
    let table = if map1 { &MAP1 } else { &MAP0 };
    table.get(usize::from(opcode)).copied().unwrap_or(UNDEF)
}

/// Tells if a VEX or EVEX opcode of the `0F` map has an immediate byte.
pub(crate) const fn vex_map1_imm8(opcode: u8) -> bool {
    matches!(opcode, 0x70..=0x73 | 0xc2 | 0xc4..=0xc6)
}

/// Gives the immediate kind of an opcode of EVEX map 4 (APX forms of legacy opcodes).
pub(crate) const fn evex_map4_imm(opcode: u8) -> u8 {
    match opcode {
        0x24 | 0x2c | 0x6b | 0x80 | 0x83 | 0xc0 | 0xc1 => I_B,
        0x69 | 0x81 => I_Z,
        0xf6 => I_GRP3B,
        0xf7 => I_GRP3V,
        _ => I_NONE,
    }
}
