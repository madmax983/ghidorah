//! The const tables of the decoder (design Section 5.1).
//!
//! | Module | Content |
//! |---|---|
//! | [`attr`] | Layer 1: `ModRM` and immediate sizes of the legacy maps |
//! | [`map0`], [`map1`], [`groups`], [`x87`] | Layer 2: mnemonics and operand specs |
//! | [`mnem`] | The canonical mnemonics |
//! | [`flagtab`] | The status flag effects of each mnemonic |
//! | [`regnames`] | The register names |

pub(crate) mod attr;
pub(crate) mod flagtab;
pub(crate) mod groups;
pub(crate) mod map0;
pub(crate) mod map1;
pub mod mnem;
pub(crate) mod ops;
pub(crate) mod regnames;
pub(crate) mod x87;

/// The group numbers of [`groups::GROUPS`].
pub(crate) mod g {
    pub(crate) const G1_EB: u8 = 0;
    pub(crate) const G1_EV: u8 = 1;
    pub(crate) const G1_EVS: u8 = 2;
    pub(crate) const G1A: u8 = 3;
    pub(crate) const G2_EB_IB: u8 = 4;
    pub(crate) const G2_EV_IB: u8 = 5;
    pub(crate) const G2_EB_1: u8 = 6;
    pub(crate) const G2_EV_1: u8 = 7;
    pub(crate) const G2_EB_CL: u8 = 8;
    pub(crate) const G2_EV_CL: u8 = 9;
    pub(crate) const G3_EB: u8 = 10;
    pub(crate) const G3_EV: u8 = 11;
    pub(crate) const G4: u8 = 12;
    pub(crate) const G5: u8 = 13;
    pub(crate) const G11_EB: u8 = 14;
    pub(crate) const G11_EV: u8 = 15;
    pub(crate) const G6: u8 = 16;
    pub(crate) const G8: u8 = 17;
    pub(crate) const G12P: u8 = 18;
    pub(crate) const G12X: u8 = 19;
    pub(crate) const G13P: u8 = 20;
    pub(crate) const G13X: u8 = 21;
    pub(crate) const G14P: u8 = 22;
    pub(crate) const G14X: u8 = 23;
    pub(crate) const G0D: u8 = 24;
    /// The number of groups.
    pub(crate) const COUNT: usize = 25;
}

/// The numbers of the special forms that need code in the decoder.
pub(crate) mod s {
    /// `90`: `nop`, `pause` or `xchg`.
    pub(crate) const NOP90: u8 = 0;
    /// `98`: `cbw`, `cwde` or `cdqe`.
    pub(crate) const CBW: u8 = 1;
    /// `99`: `cwd`, `cdq` or `cqo`.
    pub(crate) const CWD: u8 = 2;
    /// `9C`: `pushf` or `pushfw`.
    pub(crate) const PUSHF: u8 = 3;
    /// `9D`: `popf` or `popfw`.
    pub(crate) const POPF: u8 = 4;
    /// `CF`: `iret`, `iretw` or `iretq`.
    pub(crate) const IRET: u8 = 5;
    /// `D8` to `DF`: x87.
    pub(crate) const X87: u8 = 6;
    /// `E3`: `jrcxz` or `jecxz`.
    pub(crate) const JRCXZ: u8 = 7;
    /// `C6 F8`: `xabort`.
    pub(crate) const XABORT: u8 = 8;
    /// `C7 F8`: `xbegin`.
    pub(crate) const XBEGIN: u8 = 9;
    /// `0F 01`: group 7.
    pub(crate) const G7: u8 = 10;
    /// `0F 18`: prefetch hints and hint `nop` forms.
    pub(crate) const HINT18: u8 = 11;
    /// `0F 1C`: `cldemote` or a hint `nop`.
    pub(crate) const HINT1C: u8 = 12;
    /// `F3 0F 1E`: `endbr64`, `endbr32` or `rdssp`.
    pub(crate) const HINT1E: u8 = 13;
    /// `0F 12`: `movlps` or `movhlps`.
    pub(crate) const MOVLPS12: u8 = 14;
    /// `0F 16`: `movhps` or `movlhps`.
    pub(crate) const MOVHPS16: u8 = 15;
    /// `0F AE`: group 15.
    pub(crate) const G15: u8 = 16;
    /// `0F C7`: group 9.
    pub(crate) const G9: u8 = 17;
    /// A valid form outside the tables.
    pub(crate) const UNSUP: u8 = 18;
    /// `0F A6` and `0F A7`: the VIA padlock forms.
    pub(crate) const PADLOCK: u8 = 19;
    /// `F2 0F 00`: `lkgs` or group 6.
    pub(crate) const LKGS: u8 = 20;
}
