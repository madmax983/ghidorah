//! The PE32+ x86-64 loader (design Sections 4.9 to 4.15, ADR-0029).
//!
//! The loader follows the Windows loader, not a strict reading of the specification. Every
//! table read by RVA goes through the [`MemoryMap`], so a parser sees the bytes that the map
//! gives. Only a cut main header is fatal. A bad table gives a diagnostic.
//!
//! | Module | Content | Design |
//! |---|---|---|
//! | `headers` | DOS, COFF and optional headers, data directories | Section 4.9 |
//! | `sections` | the section table, the regions and the segments | Section 4.10 |
//! | `imports` | imports, delay imports and the IAT symbols | Section 4.11 |
//! | `exports` | exports, forwarders and the export symbols | Section 4.12 |
//! | `relocs` | base relocation blocks | Section 4.13 |
//! | `tls` | TLS callbacks | Section 4.13 |
//! | `debug` | the `CodeView` identity | Section 4.13 |
//! | [`pdata`] | `RUNTIME_FUNCTION` entries and unwind chains | Section 4.14 |
//! | `checksec` | the protections of `DllCharacteristics` | Section 4.13 |

mod checksec;
mod debug;
mod exports;
mod headers;
mod imports;
pub mod pdata;
mod relocs;
mod sections;
mod tls;

pub use relocs::{REL_ABSOLUTE, REL_DIR64, REL_HIGHLOW};

use std::borrow::Cow;
use std::sync::Arc;

use ghidorah_base::{BinText, DiagCode, Limits};

use crate::binary::{Arch, Binary, Entry, EntryKind, Format, Kind, PeHeaders};
use crate::diag::{Diagnostic, Diags, LoadError};
use crate::limits::Budget;
use crate::memmap::{MemoryMap, Perms};

/// The COFF `Machine` of AMD64.
pub const MACHINE_AMD64: u16 = 0x8664;

/// The optional header magic of PE32+.
pub const MAGIC_PE32_PLUS: u16 = 0x20b;

/// `IMAGE_FILE_DLL` in the COFF `Characteristics`.
pub const FILE_DLL: u16 = 0x2000;

/// The parse context of one PE load: the file, the map, the image base and the diagnostics.
pub(crate) struct Px<'a> {
    /// The file bytes.
    pub(crate) bytes: &'a [u8],
    /// The memory map of the image.
    pub(crate) map: &'a MemoryMap,
    /// The image base.
    pub(crate) base: u64,
    /// The diagnostics.
    pub(crate) diags: Diags,
    /// The caps and counters.
    pub(crate) budget: Budget,
}

impl<'a> Px<'a> {
    /// Adds a diagnostic.
    pub(crate) fn diag(&mut self, diag: Diagnostic) {
        self.diags.push(diag);
    }

    /// Gives the VA of `rva`. An overflow gives `E_OVERFLOW` and `None`.
    pub(crate) fn va(&mut self, rva: u32, path: &str) -> Option<u64> {
        let va = self.base.checked_add(u64::from(rva));
        if va.is_none() {
            self.diag(
                Diagnostic::new(DiagCode::Overflow, path)
                    .at(u64::from(rva))
                    .need(self.base),
            );
        }
        va
    }

    /// Gives the RVA of `va`, or `None` below the image base or above 4 GiB from it.
    pub(crate) fn rva_of(&self, va: u64) -> Option<u32> {
        va.checked_sub(self.base)
            .and_then(|r| u32::try_from(r).ok())
    }

    /// Gives the number of mapped bytes from `va` to the end of its region.
    pub(crate) fn avail(&self, va: u64) -> u64 {
        self.map
            .region_at(va)
            .and_then(|r| r.va.last.checked_sub(va))
            .map_or(0, |n| n.saturating_add(1))
    }

    /// Reads `len` bytes at `rva`. A read outside the map gives `E_OOB` and `None`.
    pub(crate) fn read(&mut self, rva: u32, len: u64, path: &str) -> Option<Cow<'a, [u8]>> {
        let va = self.va(rva, path)?;
        let map: &'a MemoryMap = self.map;
        if let Ok(bytes) = map.read(va, len, &self.budget.limits) {
            return Some(bytes);
        }
        let have = self.avail(va);
        self.diags.push(
            Diagnostic::new(DiagCode::Oob, path)
                .at(u64::from(rva))
                .need(len)
                .have(have),
        );
        None
    }

    /// Reads a little-endian `u16` at `rva`.
    pub(crate) fn u16_at(&mut self, rva: u32, path: &str) -> Option<u16> {
        let b = self.read(rva, 2, path)?;
        Some(u16::from_le_bytes(b.get(..2)?.try_into().ok()?))
    }

    /// Reads a little-endian `u32` at `rva`.
    pub(crate) fn u32_at(&mut self, rva: u32, path: &str) -> Option<u32> {
        let b = self.read(rva, 4, path)?;
        Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
    }

    /// Reads a little-endian `u64` at `rva`.
    pub(crate) fn u64_at(&mut self, rva: u32, path: &str) -> Option<u64> {
        let b = self.read(rva, 8, path)?;
        Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
    }

    /// Reads the C string at `rva` without its NUL byte, under the string and text caps.
    ///
    /// A string longer than the string limit gets cut with `E_LIMIT`. A string with no NUL
    /// byte before the end of its region gives `E_OOB`. A start outside the map gives `None`.
    pub(crate) fn cstr(&mut self, rva: u32, path: &str) -> Option<BinText> {
        let va = self.va(rva, path)?;
        let limit = self.budget.limits.string_len;
        let len = self.avail(va).min(limit.saturating_add(1));
        if len == 0 {
            self.diag(Diagnostic::new(DiagCode::Oob, path).at(u64::from(rva)));
            return None;
        }
        let map: &'a MemoryMap = self.map;
        let bytes = map.read(va, len, &self.budget.limits).ok()?;
        let text: &[u8] = match bytes.iter().position(|b| *b == 0) {
            Some(end) => bytes.get(..end).unwrap_or_default(),
            None if len > limit => {
                self.diags.push(
                    Diagnostic::new(DiagCode::Limit, path)
                        .at(u64::from(rva))
                        .have(limit),
                );
                bytes
                    .get(..usize::try_from(limit).unwrap_or(usize::MAX))
                    .unwrap_or_default()
            }
            None => {
                self.diags.push(
                    Diagnostic::new(DiagCode::Oob, path)
                        .at(u64::from(rva))
                        .hint("the string has no NUL byte"),
                );
                &bytes
            }
        };
        let size = u64::try_from(text.len()).unwrap_or(u64::MAX);
        Some(if self.budget.take_text(size, path, &mut self.diags) {
            BinText::new(text)
        } else {
            BinText::default()
        })
    }

    /// Tells if `va` is in a region with execute access.
    pub(crate) fn is_exec(&self, va: u64) -> bool {
        self.map
            .region_at(va)
            .is_some_and(|r| r.perms.contains(Perms::EXECUTE))
    }
}

/// Gives the data directory `index` when it is present: RVA and size both above 0.
fn dir(b: &Binary, index: u8) -> Option<(u32, u32)> {
    b.data_dirs
        .iter()
        .find(|d| d.index == index && d.rva != 0 && d.size != 0)
        .map(|d| (d.rva, d.size))
}

/// Loads a PE32+ AMD64 file. The probe found the `PE\0\0` signature.
///
/// # Errors
///
/// Returns [`LoadError::Malformed`] with `E_OOB` when the COFF header or the fixed part of the
/// optional header is cut.
pub fn load(
    file: &Arc<[u8]>,
    sha256: [u8; 32],
    limits: &Limits,
) -> Result<(Binary, MemoryMap), LoadError> {
    let bytes: &[u8] = file;
    let h = headers::parse(bytes)?;
    let file_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut diags = Diags::default();
    let kind = if h.characteristics & FILE_DLL != 0 {
        Kind::Dyn
    } else {
        Kind::Exec
    };
    let arch = if h.machine == MACHINE_AMD64 {
        Arch::X86_64
    } else {
        Arch::Other(h.machine)
    };
    let mut b = Binary::empty(Format::Pe32Plus, arch, kind, sha256);
    b.image_base = h.image_base;
    b.pe = Some(PeHeaders {
        magic: h.magic,
        machine: h.machine,
        characteristics: h.characteristics,
        dll_characteristics: h.dll_characteristics,
        subsystem: h.subsystem,
        section_alignment: h.section_alignment,
        file_alignment: h.file_alignment,
        size_of_image: h.size_of_image,
        size_of_headers: h.header_size,
    });
    b.data_dirs = headers::dirs(bytes, &h, &mut diags);
    b.sections = sections::parse(bytes, &h, limits, &mut diags);
    let (map, segments) = sections::map(Arc::clone(file), &h, &b.sections, &mut diags);
    b.segments = segments;
    let mut px = Px {
        bytes,
        map: &map,
        base: h.image_base,
        diags,
        budget: Budget::new(limits, file_len),
    };
    tables(&mut px, &h, &mut b);
    let (diagnostics, dropped) = px.diags.into_parts();
    b.diagnostics = diagnostics;
    b.diagnostics_dropped = dropped;
    Ok((b, map))
}

/// Reads the tables of the data directories and the entry points.
fn tables(px: &mut Px<'_>, h: &headers::Headers, b: &mut Binary) {
    if let Some((rva, _)) = dir(b, 1) {
        imports::load(px, rva, b);
    }
    if let Some((rva, _)) = dir(b, 13) {
        imports::load_delay(px, rva, b);
    }
    if let Some((rva, size)) = dir(b, 0) {
        exports::load(px, rva, size, b);
    }
    if let Some((rva, size)) = dir(b, 5) {
        b.relocs = relocs::load(px, rva, size, b);
    }
    let mut entries = Vec::new();
    if h.entry != 0
        && let Some(addr) = px.va(h.entry, "pe.optional.AddressOfEntryPoint")
    {
        entries.push(Entry {
            addr,
            kind: EntryKind::Entry,
        });
    }
    for e in &b.exports {
        if let Some(addr) = e.addr.filter(|a| px.is_exec(*a)) {
            entries.push(Entry {
                addr,
                kind: EntryKind::Export,
            });
        }
    }
    if let Some((rva, _)) = dir(b, 9) {
        entries.extend(tls::load(px, rva));
    }
    entries.sort_unstable();
    entries.dedup();
    b.entry_points = entries;
    if let Some((rva, size)) = dir(b, 6) {
        b.identity.codeview = debug::load(px, rva, size);
    }
    if let Some((rva, size)) = dir(b, 3) {
        b.pdata = pdata::load(px, rva, size);
    }
    b.protections = Some(checksec::protections(h.dll_characteristics));
}
