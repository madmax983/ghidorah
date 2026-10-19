//! The DOS header, the COFF header, the PE32+ optional header and the data directories (design
//! Section 4.9).
//!
//! | Field | Rule |
//! |---|---|
//! | `e_lfanew` | the `u32` at 0x3C; the probe found `PE\0\0` there |
//! | COFF header | 20 bytes after the signature; a cut header is fatal (`E_OOB`) |
//! | optional header | the 112 fixed bytes of PE32+; a cut header is fatal (`E_OOB`) |
//! | `SizeOfOptionalHeader` | the distance to the section table; below 112 gives `E_BAD_ENTSIZE` |
//! | `NumberOfRvaAndSizes` | above 16 counts as 16; the directories must fit `SizeOfOptionalHeader` |

use ghidorah_base::DiagCode;
use ghidorah_kernel::{Endian, Reader};

use crate::binary::DataDir;
use crate::diag::{Diagnostic, Diags, LoadError};

/// The size of the COFF header.
const COFF_SIZE: usize = 20;

/// The size of the fixed part of the PE32+ optional header.
pub(crate) const OPT_FIXED: u64 = 112;

/// The largest number of data directories.
pub(crate) const MAX_DIRS: u32 = 16;

/// The fields of the headers that the loader uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Headers {
    /// The COFF `Machine`.
    pub(crate) machine: u16,
    /// `NumberOfSections`.
    pub(crate) sections: u16,
    /// `SizeOfOptionalHeader`.
    pub(crate) opt_size: u16,
    /// The COFF `Characteristics`.
    pub(crate) characteristics: u16,
    /// The file offset of the optional header.
    pub(crate) opt_off: u64,
    /// The optional header magic.
    pub(crate) magic: u16,
    /// `AddressOfEntryPoint`.
    pub(crate) entry: u32,
    /// `ImageBase`.
    pub(crate) image_base: u64,
    /// `SectionAlignment`.
    pub(crate) section_alignment: u32,
    /// `FileAlignment`.
    pub(crate) file_alignment: u32,
    /// `SizeOfImage`.
    pub(crate) size_of_image: u32,
    /// `SizeOfHeaders`.
    pub(crate) header_size: u32,
    /// `Subsystem`.
    pub(crate) subsystem: u16,
    /// `DllCharacteristics`.
    pub(crate) dll_characteristics: u16,
    /// `NumberOfRvaAndSizes`.
    pub(crate) rva_count: u32,
}

/// Gives the error of a cut main header.
fn cut(path: &str, need: u64, have: u64) -> LoadError {
    LoadError::Malformed(Diagnostic::new(DiagCode::Oob, path).need(need).have(have))
}

/// Parses the main headers.
///
/// # Errors
///
/// Returns [`LoadError::Malformed`] with `E_OOB` when the COFF header or the 112 fixed bytes of
/// the optional header are cut.
pub(crate) fn parse(bytes: &[u8]) -> Result<Headers, LoadError> {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let lfanew = bytes
        .get(0x3c..0x40)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_le_bytes);
    let coff = usize::try_from(lfanew)
        .ok()
        .and_then(|l| l.checked_add(4))
        .ok_or_else(|| cut("pe.coff", 0, len))?;
    let opt = coff
        .checked_add(COFF_SIZE)
        .ok_or_else(|| cut("pe.coff", 0, len))?;
    let fixed = usize::try_from(OPT_FIXED).unwrap_or(usize::MAX);
    let Some(head) = bytes.get(coff..opt) else {
        return Err(cut("pe.coff", u64::try_from(opt).unwrap_or(u64::MAX), len));
    };
    let end = opt.saturating_add(fixed);
    let Some(body) = bytes.get(opt..end) else {
        return Err(cut(
            "pe.optional",
            u64::try_from(end).unwrap_or(u64::MAX),
            len,
        ));
    };
    let mut c = Reader::new(head, Endian::Little);
    let machine = c.u16().unwrap_or(0);
    let sections = c.u16().unwrap_or(0);
    let _ = c.skip(12);
    let opt_size = c.u16().unwrap_or(0);
    let characteristics = c.u16().unwrap_or(0);
    let mut o = Reader::new(body, Endian::Little);
    let magic = o.u16().unwrap_or(0);
    let _ = o.skip(14);
    let entry = o.u32().unwrap_or(0);
    let _ = o.skip(4);
    let image_base = o.u64().unwrap_or(0);
    let section_alignment = o.u32().unwrap_or(0);
    let file_alignment = o.u32().unwrap_or(0);
    let _ = o.skip(16);
    let size_of_image = o.u32().unwrap_or(0);
    let header_size = o.u32().unwrap_or(0);
    let _ = o.skip(4);
    let subsystem = o.u16().unwrap_or(0);
    let dll_characteristics = o.u16().unwrap_or(0);
    let _ = o.skip(36);
    let rva_count = o.u32().unwrap_or(0);
    Ok(Headers {
        machine,
        sections,
        opt_size,
        characteristics,
        opt_off: u64::try_from(opt).unwrap_or(u64::MAX),
        magic,
        entry,
        image_base,
        section_alignment,
        file_alignment,
        size_of_image,
        header_size,
        subsystem,
        dll_characteristics,
        rva_count,
    })
}

/// Reads the data directories that `NumberOfRvaAndSizes` and `SizeOfOptionalHeader` allow.
pub(crate) fn dirs(bytes: &[u8], h: &Headers, diags: &mut Diags) -> Vec<DataDir> {
    let opt_size = u64::from(h.opt_size);
    if opt_size < OPT_FIXED {
        diags.push(
            Diagnostic::new(DiagCode::BadEntsize, "pe.coff.SizeOfOptionalHeader")
                .need(OPT_FIXED)
                .have(opt_size),
        );
        return Vec::new();
    }
    let room = opt_size.saturating_sub(OPT_FIXED) / 8;
    let mut count = u64::from(h.rva_count.min(MAX_DIRS));
    if count > room {
        diags.push(
            Diagnostic::new(DiagCode::Oob, "pe.optional.DataDirectory")
                .need(count.saturating_mul(8))
                .have(room.saturating_mul(8)),
        );
        count = room;
    }
    let start = h.opt_off.saturating_add(OPT_FIXED);
    let mut out = Vec::new();
    for index in 0..count {
        let at = start.saturating_add(index.saturating_mul(8));
        let entry = usize::try_from(at).ok().and_then(|a| {
            let end = a.checked_add(8)?;
            bytes.get(a..end)
        });
        let Some(entry) = entry else {
            diags.push(Diagnostic::new(DiagCode::Oob, "pe.optional.DataDirectory").at(at));
            break;
        };
        let mut r = Reader::new(entry, Endian::Little);
        out.push(DataDir {
            index: u8::try_from(index).unwrap_or(u8::MAX),
            rva: r.u32().unwrap_or(0),
            size: r.u32().unwrap_or(0),
        });
    }
    out
}
