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
    /// No region holds the target of an indirect pointer.
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

/// `DW_EH_PE_omit`: no pointer.
const OMIT: u8 = 0xff;
/// The bit of an indirect pointer.
const INDIRECT: u8 = 0x80;

/// A raw value: unsigned or signed.
#[derive(Debug, Clone, Copy)]
enum Raw {
    Unsigned(u64),
    Signed(i64),
}

impl Raw {
    /// Gives the value as a 64-bit pattern.
    const fn bits(self) -> u64 {
        match self {
            Self::Unsigned(v) => v,
            Self::Signed(v) => v.cast_unsigned(),
        }
    }
}

/// Tells if the low 4 bits of `enc` name a known value format.
const fn known_format(enc: u8) -> bool {
    matches!(enc & 0x0f, 0x00..=0x04 | 0x08..=0x0c)
}

const fn map_read(e: ghidorah_kernel::ReadError) -> PointerError {
    match e {
        ghidorah_kernel::ReadError::BadLeb => PointerError::BadLeb,
        ghidorah_kernel::ReadError::Eof | ghidorah_kernel::ReadError::NoNul => PointerError::Eof,
    }
}

/// Reads the value of the format in the low 4 bits of `enc`.
fn read_raw(reader: &mut Reader<'_>, enc: u8) -> Result<Raw, PointerError> {
    let raw = match enc & 0x0f {
        0x00 | 0x04 => Raw::Unsigned(reader.u64().map_err(map_read)?),
        0x01 => Raw::Unsigned(reader.uleb128().map_err(map_read)?),
        0x02 => Raw::Unsigned(u64::from(reader.u16().map_err(map_read)?)),
        0x03 => Raw::Unsigned(u64::from(reader.u32().map_err(map_read)?)),
        0x08 | 0x0c => Raw::Signed(reader.u64().map_err(map_read)?.cast_signed()),
        0x09 => Raw::Signed(reader.sleb128().map_err(map_read)?),
        0x0a => Raw::Signed(i64::from(reader.u16().map_err(map_read)?.cast_signed())),
        0x0b => Raw::Signed(i64::from(reader.u32().map_err(map_read)?.cast_signed())),
        _ => return Err(PointerError::Encoding(enc)),
    };
    Ok(raw)
}

/// Reads a value of the format in the low 4 bits of `enc`, with no base and no indirection.
///
/// An FDE PC range uses this form.
pub(crate) fn read_value(reader: &mut Reader<'_>, enc: u8) -> Result<u64, PointerError> {
    if !known_format(enc) {
        return Err(PointerError::Encoding(enc));
    }
    read_raw(reader, enc).map(Raw::bits)
}

/// Tells if `enc` is a pointer encoding of the module table.
pub(crate) const fn supported(enc: u8) -> bool {
    enc == OMIT || (known_format(enc) && matches!(enc & 0x70, 0x00 | 0x10 | 0x30))
}

/// Adds a raw value to a base. An 8-byte unsigned value is a two's complement offset.
fn offset(base: u64, raw: Raw, enc: u8) -> Option<u64> {
    match raw {
        Raw::Signed(v) => base.checked_add_signed(v),
        Raw::Unsigned(v) if matches!(enc & 0x0f, 0x00 | 0x04) => {
            base.checked_add_signed(v.cast_signed())
        }
        Raw::Unsigned(v) => base.checked_add(v),
    }
}

/// Reads one pointer with the encoding `enc` at the reader position.
///
/// Gives `Ok(None)` for `DW_EH_PE_omit` and reads no byte. An indirect pointer reads its
/// target through `mem`.
///
/// # Errors
///
/// Returns [`PointerError::Eof`] or [`PointerError::BadLeb`] for a bad value.
/// Returns [`PointerError::Encoding`] for an encoding outside the table of the module.
/// Returns [`PointerError::Overflow`] when the address passes `u64::MAX`.
/// Returns [`PointerError::Unmapped`] for an indirect target outside `mem`.
/// A bad encoding or a bad value keeps the reader position.
pub fn read_pointer(
    reader: &mut Reader<'_>,
    enc: u8,
    bases: Bases,
    mem: Option<&MemoryMap>,
) -> Result<Option<u64>, PointerError> {
    if enc == OMIT {
        return Ok(None);
    }
    if !supported(enc) {
        return Err(PointerError::Encoding(enc));
    }
    let field = u64::try_from(reader.pos())
        .ok()
        .and_then(|pos| bases.start.checked_add(pos));
    let raw = read_raw(reader, enc)?;
    let addr = match enc & 0x70 {
        0x10 => field.and_then(|f| offset(f, raw, enc)),
        0x30 => offset(bases.data, raw, enc),
        _ => Some(raw.bits()),
    }
    .ok_or(PointerError::Overflow)?;
    if enc & INDIRECT == 0 {
        return Ok(Some(addr));
    }
    let target = mem
        .and_then(|m| m.read(addr, 8, &ghidorah_base::Limits::DEFAULT).ok())
        .and_then(|b| <[u8; 8]>::try_from(b.as_ref()).ok())
        .ok_or(PointerError::Unmapped(addr))?;
    Ok(Some(u64::from_le_bytes(target)))
}
