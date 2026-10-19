//! Data models (design Section 9.1).
//!
//! A data model gives the size and the alignment of each primitive type. Layout is a
//! function of a record and a data model. The store never keeps a layout.

use crate::ty::Prim;

/// The size and the alignment of a type, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SizeAlign {
    /// The size in bytes.
    pub size: u64,
    /// The alignment in bytes. It is a power of two.
    pub align: u64,
}

impl SizeAlign {
    /// Makes a value with the same size and alignment.
    #[must_use]
    pub const fn same(bytes: u64) -> Self {
        Self {
            size: bytes,
            align: bytes,
        }
    }
}

/// A data model preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DataModel {
    /// The preset name, for example `x86_64-sysv`.
    pub name: &'static str,
    /// `true` when plain `char` is signed.
    pub char_signed: bool,
    /// `true` when `wchar_t` is signed.
    pub wchar_signed: bool,
    /// `_Bool`.
    pub boolean: SizeAlign,
    /// `short` and `unsigned short`.
    pub short: SizeAlign,
    /// `int`, `unsigned int` and an enum whose values fit in 32 bits.
    pub int: SizeAlign,
    /// `long` and `unsigned long`.
    pub long: SizeAlign,
    /// `long long` and `unsigned long long`.
    pub long_long: SizeAlign,
    /// `__int128` and `unsigned __int128`.
    pub int128: SizeAlign,
    /// A data pointer and a function pointer.
    pub pointer: SizeAlign,
    /// `float`.
    pub float: SizeAlign,
    /// `double`.
    pub double: SizeAlign,
    /// `long double`.
    pub long_double: SizeAlign,
    /// `wchar_t`.
    pub wchar: SizeAlign,
}

impl DataModel {
    /// The x86-64 System V preset of ELF binaries.
    pub const X86_64_SYSV: Self = Self {
        name: "x86_64-sysv",
        char_signed: true,
        wchar_signed: true,
        boolean: SizeAlign::same(1),
        short: SizeAlign::same(2),
        int: SizeAlign::same(4),
        long: SizeAlign::same(8),
        long_long: SizeAlign::same(8),
        int128: SizeAlign::same(16),
        pointer: SizeAlign::same(8),
        float: SizeAlign::same(4),
        double: SizeAlign::same(8),
        long_double: SizeAlign::same(16),
        wchar: SizeAlign::same(4),
    };

    /// The x86-64 Windows (LLP64) preset of PE binaries: `long` has 4 bytes, `long double`
    /// has 8 bytes and `wchar_t` is an unsigned 2-byte type.
    pub const X86_64_WIN: Self = Self {
        name: "x86_64-win",
        char_signed: true,
        wchar_signed: false,
        boolean: SizeAlign::same(1),
        short: SizeAlign::same(2),
        int: SizeAlign::same(4),
        long: SizeAlign::same(4),
        long_long: SizeAlign::same(8),
        int128: SizeAlign::same(16),
        pointer: SizeAlign::same(8),
        float: SizeAlign::same(4),
        double: SizeAlign::same(8),
        long_double: SizeAlign::same(8),
        wchar: SizeAlign::same(2),
    };

    /// Gives the size and the alignment of a primitive type. `void` has none.
    #[must_use]
    pub const fn prim(&self, prim: Prim) -> Option<SizeAlign> {
        let one = SizeAlign::same(1);
        Some(match prim {
            Prim::Void => return None,
            Prim::Bool => self.boolean,
            Prim::Char | Prim::SChar | Prim::UChar => one,
            Prim::Short | Prim::UShort => self.short,
            Prim::Int | Prim::UInt => self.int,
            Prim::Long | Prim::ULong => self.long,
            Prim::LongLong | Prim::ULongLong => self.long_long,
            Prim::Int128 | Prim::UInt128 => self.int128,
            Prim::Float => self.float,
            Prim::Double => self.double,
            Prim::LongDouble => self.long_double,
            Prim::WChar => self.wchar,
        })
    }

    /// Tells if the integer type `prim` is signed in this model.
    #[must_use]
    pub const fn is_signed(&self, prim: Prim) -> bool {
        match prim {
            Prim::Char => self.char_signed,
            Prim::WChar => self.wchar_signed,
            Prim::SChar | Prim::Short | Prim::Int | Prim::Long | Prim::LongLong | Prim::Int128 => {
                true
            }
            _ => false,
        }
    }
}
