//! The ELF64 file header and the escape values of section 0 (design Section 4.3).

use ghidorah_base::DiagCode;

use super::consts::{EHDR_SIZE, PN_XNUM, SHDR_SIZE};
use super::view::{Cx, Fields};
use crate::diag::{Diagnostic, LoadError};

/// The fields of the file header that the loader uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    /// `e_type`.
    pub(crate) e_type: u16,
    /// `e_machine`.
    pub(crate) machine: u16,
    /// `e_entry`.
    pub(crate) entry: u64,
    /// `e_phoff`.
    pub(crate) phoff: u64,
    /// `e_shoff`.
    pub(crate) shoff: u64,
    /// `e_phentsize`.
    pub(crate) phentsize: u16,
    /// `e_phnum`.
    pub(crate) phnum: u16,
    /// `e_shentsize`.
    pub(crate) shentsize: u16,
    /// `e_shnum`.
    pub(crate) shnum: u16,
    /// `e_shstrndx`.
    pub(crate) shstrndx: u16,
}

/// Parses the file header. The probe checked the identification bytes.
///
/// # Errors
///
/// Returns [`LoadError::Malformed`] with `E_OOB` when the file has fewer than 64 bytes.
pub(crate) fn parse(bytes: &[u8]) -> Result<Header, LoadError> {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let ehdr = usize::try_from(EHDR_SIZE).unwrap_or(usize::MAX);
    let Some(head) = bytes.get(..ehdr) else {
        return Err(LoadError::Malformed(
            Diagnostic::new(DiagCode::Oob, "elf.ehdr")
                .need(EHDR_SIZE)
                .have(len),
        ));
    };
    let mut f = Fields::new(head.get(16..).unwrap_or_default());
    let e_type = f.u16();
    let machine = f.u16();
    let _version = f.u32();
    let entry = f.u64();
    let phoff = f.u64();
    let shoff = f.u64();
    let _flags = f.u32();
    let _ehsize = f.u16();
    Ok(Header {
        e_type,
        machine,
        entry,
        phoff,
        shoff,
        phentsize: f.u16(),
        phnum: f.u16(),
        shentsize: f.u16(),
        shnum: f.u16(),
        shstrndx: f.u16(),
    })
}

/// The section header table after the escape values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Counts {
    /// The program header count.
    pub(crate) phnum: u64,
    /// The section header count. It is 0 when the file has no usable table.
    pub(crate) shnum: u64,
    /// The index of the section name table. 0 means no names.
    pub(crate) shstrndx: u64,
}

/// Resolves `e_phnum`, `e_shnum` and `e_shstrndx` through section 0.
///
/// `e_phnum == 0xffff` reads `sh_info`, `e_shnum == 0` reads `sh_size` and
/// `e_shstrndx == 0xffff` reads `sh_link` of section 0. A cut section 0 gives no table.
pub(crate) fn counts(cx: &mut Cx<'_>, h: &Header) -> Counts {
    let mut out = Counts {
        phnum: u64::from(h.phnum),
        shnum: u64::from(h.shnum),
        shstrndx: u64::from(h.shstrndx),
    };
    if h.shoff == 0 {
        out.shnum = 0;
        out.shstrndx = 0;
        return out;
    }
    if u64::from(h.shentsize) < SHDR_SIZE {
        cx.diag(
            Diagnostic::new(DiagCode::BadEntsize, "elf.ehdr.e_shentsize")
                .need(SHDR_SIZE)
                .have(u64::from(h.shentsize)),
        );
        out.shnum = 0;
        return out;
    }
    // A cut section 0 means no table: its escape values are not in the file.
    let s0 = cx
        .file_range(h.shoff, SHDR_SIZE, "elf.shdr[0]")
        .filter(|s| u64::try_from(s.len()).is_ok_and(|n| n >= SHDR_SIZE));
    let Some(s0) = s0 else {
        out.shnum = 0;
        out.shstrndx = 0;
        return out;
    };
    let mut f = Fields::new(s0.get(32..).unwrap_or_default());
    let size = f.u64();
    let link = f.u32();
    let info = f.u32();
    if h.phnum == PN_XNUM {
        out.phnum = u64::from(info);
    }
    if h.shnum == 0 {
        out.shnum = size;
    }
    if h.shstrndx == 0xffff {
        out.shstrndx = u64::from(link);
    }
    out
}
