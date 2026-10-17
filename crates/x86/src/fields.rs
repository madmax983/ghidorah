//! The encoding fields of an instruction: map, encoding family, prefixes and raw fields.

/// The opcode map of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Map {
    /// The one-byte map.
    #[default]
    One = 0,
    /// The `0F` map.
    M0F = 1,
    /// The `0F 38` map.
    M0F38 = 2,
    /// The `0F 3A` map.
    M0F3A = 3,
    /// EVEX map 4 (APX forms of legacy instructions).
    Map4 = 4,
    /// VEX or EVEX map 5.
    Map5 = 5,
    /// VEX or EVEX map 6.
    Map6 = 6,
    /// VEX or EVEX map 7.
    Map7 = 7,
    /// XOP map 8.
    Xop8 = 8,
    /// XOP map 9.
    Xop9 = 9,
    /// XOP map 10.
    XopA = 10,
}

impl Map {
    /// Gives the display name: `map0`, `0f`, `0f38`, `0f3a`, `map4` to `map7`, `xop8`,
    /// `xop9` or `xopa`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::One => "map0",
            Self::M0F => "0f",
            Self::M0F38 => "0f38",
            Self::M0F3A => "0f3a",
            Self::Map4 => "map4",
            Self::Map5 => "map5",
            Self::Map6 => "map6",
            Self::Map7 => "map7",
            Self::Xop8 => "xop8",
            Self::Xop9 => "xop9",
            Self::XopA => "xopa",
        }
    }

    /// Gives the map of a VEX or EVEX map number, 0 to 7.
    #[must_use]
    pub(crate) const fn from_number(n: u8) -> Self {
        match n {
            1 => Self::M0F,
            2 => Self::M0F38,
            3 => Self::M0F3A,
            4 => Self::Map4,
            5 => Self::Map5,
            6 => Self::Map6,
            7 => Self::Map7,
            8 => Self::Xop8,
            9 => Self::Xop9,
            10 => Self::XopA,
            _ => Self::One,
        }
    }
}

/// The encoding family of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum Encoding {
    /// Legacy prefixes, an optional REX prefix and an opcode.
    #[default]
    Legacy = 0,
    /// The two-byte APX prefix `D5`.
    Rex2 = 1,
    /// The two-byte VEX prefix `C5`.
    Vex2 = 2,
    /// The three-byte VEX prefix `C4`.
    Vex3 = 3,
    /// The four-byte EVEX prefix `62`.
    Evex = 4,
    /// The three-byte AMD XOP prefix `8F`.
    Xop = 5,
}

impl Encoding {
    /// Gives the stable name, for example `vex3`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Rex2 => "rex2",
            Self::Vex2 => "vex2",
            Self::Vex3 => "vex3",
            Self::Evex => "evex",
            Self::Xop => "xop",
        }
    }
}

/// The identity of an opaque form (design Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpaqueForm {
    /// The encoding family.
    pub encoding: Encoding,
    /// The opcode map.
    pub map: Map,
    /// The opcode byte.
    pub opcode: u8,
    /// The instruction length.
    pub len: u8,
}

/// The legacy and REX prefixes of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PrefixSet(pub(crate) u16);

impl PrefixSet {
    pub(crate) const LOCK: u16 = 1;
    pub(crate) const REP: u16 = 1 << 1;
    pub(crate) const REPNE: u16 = 1 << 2;
    pub(crate) const OSZ: u16 = 1 << 3;
    pub(crate) const ASZ: u16 = 1 << 4;
    pub(crate) const REX: u16 = 1 << 5;
    pub(crate) const REX_W: u16 = 1 << 6;
    pub(crate) const OSZ_USED: u16 = 1 << 7;
    pub(crate) const ASZ_USED: u16 = 1 << 12;
    pub(crate) const REP_USED: u16 = 1 << 13;

    /// Tells if a `F0` (`lock`) prefix is present.
    #[must_use]
    pub const fn lock(self) -> bool {
        self.0 & Self::LOCK != 0
    }

    /// Tells if the last `F2` or `F3` prefix is `F3` (`rep`).
    #[must_use]
    pub const fn rep(self) -> bool {
        self.0 & Self::REP != 0
    }

    /// Tells if the last `F2` or `F3` prefix is `F2` (`repne`).
    #[must_use]
    pub const fn repne(self) -> bool {
        self.0 & Self::REPNE != 0
    }

    /// Tells if a `66` (operand size) prefix is present.
    #[must_use]
    pub const fn osz(self) -> bool {
        self.0 & Self::OSZ != 0
    }

    /// Tells if a `67` (address size) prefix is present.
    #[must_use]
    pub const fn asz(self) -> bool {
        self.0 & Self::ASZ != 0
    }

    /// Tells if a REX prefix or a REX2 prefix is present.
    #[must_use]
    pub const fn rex(self) -> bool {
        self.0 & Self::REX != 0
    }

    /// Tells if the REX or REX2 prefix has the `W` bit.
    #[must_use]
    pub const fn rex_w(self) -> bool {
        self.0 & Self::REX_W != 0
    }

    /// Gives the number of `66` prefix bytes.
    #[must_use]
    pub const fn count_66(self) -> u8 {
        ((self.0 >> 8) & 0xf) as u8
    }

    /// Tells if the instruction uses its `66` prefix for the operand size or as a
    /// mandatory prefix.
    #[must_use]
    pub const fn osz_used(self) -> bool {
        self.0 & Self::OSZ_USED != 0
    }

    pub(crate) const fn asz_used(self) -> bool {
        self.0 & Self::ASZ_USED != 0
    }

    pub(crate) const fn rep_used(self) -> bool {
        self.0 & Self::REP_USED != 0
    }
}

/// The raw encoding fields of an instruction, for the printer and the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RawFields {
    /// The encoding family.
    pub encoding: Encoding,
    /// The opcode map.
    pub map: Map,
    /// The offset of the opcode byte.
    pub opcode_off: u8,
    /// The opcode byte.
    pub opcode: u8,
    /// The REX byte, or the payload of a REX2 prefix.
    pub rex: Option<u8>,
    /// The `ModRM` byte.
    pub modrm: Option<u8>,
    /// The SIB byte.
    pub sib: Option<u8>,
    /// The offset of the displacement.
    pub disp_off: u8,
    /// The displacement size in bytes, 0, 1, 2, 4 or 8.
    pub disp_size: u8,
    /// The offset of the immediate bytes.
    pub imm_off: u8,
    /// The number of immediate bytes, both immediates included.
    pub imm_size: u8,
}
