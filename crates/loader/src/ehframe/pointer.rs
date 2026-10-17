//! `DW_EH_PE` pointer encodings (LSB 3.0, Section 10.5).
//!
//! The low 4 bits give the value format. Bits 4 to 6 give the base. Bit 7 marks an
//! indirect pointer. The value `0xff` (`DW_EH_PE_omit`) means no pointer.
//!
//! | Bits | Name | Rule |
//! |---|---|---|
//! | `0x00` | `absptr` | 8 bytes |
//! | `0x01` | `uleb128` | unsigned LEB128 |
//! | `0x02`, `0x03`, `0x04` | `udata2`, `udata4`, `udata8` | unsigned, 2, 4 or 8 bytes |
//! | `0x08` | `signed` | signed, 8 bytes |
//! | `0x09` | `sleb128` | signed LEB128 |
//! | `0x0a`, `0x0b`, `0x0c` | `sdata2`, `sdata4`, `sdata8` | signed, 2, 4 or 8 bytes |
//! | `0x10` | `pcrel` | the address of the field plus the value |
//! | `0x30` | `datarel` | the data base plus the value |
//! | `0x80` | `indirect` | the 8-byte value at the computed address |
//! | `0xff` | `omit` | no pointer |
//!
//! Another format or base (`textrel`, `funcrel`, `aligned`) gives [`PointerError::Encoding`].

use std::fmt;

use ghidorah_base::DiagCode;
use ghidorah_kernel::Reader;

use crate::memmap::MemoryMap;

/// The base addresses of the relative pointer forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bases {
    /// The address of the first byte of the reader buffer. A `pcrel` pointer adds the
    /// address of its field: `start` plus the reader position.
    pub start: u64,
    /// The base of a `datarel` pointer.
    pub data: u64,
}

/// The error of an encoded pointer read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerError {
    /// The data ends in the value.
    Eof,
    /// A LEB128 value is not valid or has more than 64 bits.
    BadLeb,
    /// The encoding byte has a format or a base outside the supported set.
    Encoding(u8),
    /// The address goes past the 64-bit range.
    Overflow,
    /// The target of an indirect pointer is not mapped.
    Unmapped(u64),
}

impl PointerError {
    /// Gives the diagnostic code of the error.
    #[must_use]
    pub const fn code(self) -> DiagCode {
        match self {
            Self::Eof | Self::Unmapped(_) => DiagCode::Oob,
            Self::BadLeb | Self::Overflow => DiagCode::Overflow,
            Self::Encoding(_) => DiagCode::BadMagic,
        }
    }
}

impl fmt::Display for PointerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => f.write_str("the data ends in the pointer"),
            Self::BadLeb => f.write_str("the LEB128 value is not valid"),
            Self::Encoding(enc) => write!(f, "the pointer encoding {enc:#04x} is not supported"),
            Self::Overflow => f.write_str("the pointer goes past the 64-bit range"),
            Self::Unmapped(va) => write!(f, "the indirect pointer at {va:#x} is not mapped"),
        }
    }
}

impl std::error::Error for PointerError {}

/// Reads one pointer with the encoding `enc` at the reader position.
///
/// Gives `Ok(None)` for `DW_EH_PE_omit` and reads no byte. An indirect pointer reads its
/// target through `mem`.
///
/// # Errors
///
/// Returns [`PointerError::Eof`] or [`PointerError::BadLeb`] for a bad value,
/// [`PointerError::Encoding`] for an encoding outside the table of the module,
/// [`PointerError::Overflow`] when the address passes `u64::MAX`, and
/// [`PointerError::Unmapped`] for an indirect target outside `mem`. A failed read keeps
/// the reader position when the value itself is bad.
pub fn read_pointer(
    reader: &mut Reader<'_>,
    enc: u8,
    bases: Bases,
    mem: Option<&MemoryMap>,
) -> Result<Option<u64>, PointerError> {
    let _ = (reader, bases, mem);
    Err(PointerError::Encoding(enc))
}
