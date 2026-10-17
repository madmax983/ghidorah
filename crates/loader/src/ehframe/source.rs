//! The place of the `.eh_frame` bytes: the section, else `PT_GNU_EH_FRAME`.

use ghidorah_base::DiagCode;
use ghidorah_kernel::{Endian, Reader};

use super::{Bases, Place, read_pointer};
use crate::binary::{Binary, SectionKind, SegmentKind};
use crate::diag::{Diagnostic, Diags};
use crate::elf::consts::{PT_GNU_EH_FRAME, SHT_NOBITS};
use crate::memmap::MemoryMap;

/// Gives `len` file bytes at `off`, cut at the end of the file with `E_OOB`.
fn file_bytes<'a>(
    file: &'a [u8],
    off: u64,
    len: u64,
    path: &str,
    diags: &mut Diags,
) -> Option<&'a [u8]> {
    let file_len = u64::try_from(file.len()).unwrap_or(u64::MAX);
    let end = off.saturating_add(len).min(file_len);
    if off > file_len || end < off.saturating_add(len) {
        diags.push(
            Diagnostic::new(DiagCode::Oob, path)
                .at(off)
                .need(len)
                .have(file_len.saturating_sub(off)),
        );
    }
    let start = usize::try_from(off).ok()?;
    let stop = usize::try_from(end).ok()?;
    file.get(start..stop)
}

/// Finds the `.eh_frame` bytes: the section, else the `eh_frame_ptr` of `.eh_frame_hdr`.
pub(super) fn source<'a>(
    binary: &Binary,
    map: &'a MemoryMap,
    diags: &mut Diags,
) -> Option<(&'a [u8], Place)> {
    let file = map.file();
    if let Some(s) = binary
        .sections
        .iter()
        .find(|s| s.name.as_bytes() == b".eh_frame")
    {
        if s.kind == SectionKind::Elf(SHT_NOBITS) || s.size == 0 {
            return None;
        }
        let path = format!("elf.shdr[{}]", s.index);
        let bytes = file_bytes(file, s.file_off, s.size, &path, diags)?;
        let place = Place {
            va: s.addr,
            file_off: s.file_off,
        };
        return Some((bytes, place));
    }
    let hdr = binary
        .segments
        .iter()
        .find(|s| s.kind == SegmentKind::Elf(PT_GNU_EH_FRAME))?;
    if hdr.file_size == 0 {
        return None;
    }
    let path = "elf.eh_frame_hdr";
    let raw = file_bytes(file, hdr.file_off, hdr.file_size, path, diags)?;
    let mut r = Reader::new(raw, Endian::Little);
    let version = r.u8().ok()?;
    if version != 1 {
        diags.push(
            Diagnostic::new(DiagCode::BadMagic, path)
                .at(hdr.file_off)
                .need(1)
                .have(u64::from(version)),
        );
        return None;
    }
    let enc = r.u8().ok()?;
    r.seek(4).ok()?;
    let bases = Bases {
        start: hdr.vaddr,
        data: hdr.vaddr,
    };
    let va = match read_pointer(&mut r, enc, bases, Some(map)) {
        Ok(va) => va?,
        Err(e) => {
            diags.push(
                Diagnostic::new(e.code(), "elf.eh_frame_hdr.eh_frame_ptr")
                    .at(hdr.file_off.saturating_add(4))
                    .hint("the eh_frame_ptr field is not valid"),
            );
            return None;
        }
    };
    let Some(bytes) = mapped_tail(map, va) else {
        diags.push(
            Diagnostic::new(DiagCode::Oob, "elf.eh_frame_hdr.eh_frame_ptr")
                .at(va)
                .hint("eh_frame_ptr names no file bytes"),
        );
        return None;
    };
    let file_off = map.va_to_file(va)?;
    Some((bytes, Place { va, file_off }))
}

/// Gives the file bytes of the region at `va` from `va` to the end of its file part.
fn mapped_tail(map: &MemoryMap, va: u64) -> Option<&[u8]> {
    let region = map.region_at(va)?;
    let off = map.va_to_file(va)?;
    let into = va.checked_sub(region.va.first)?;
    let len = region.file_size.checked_sub(into)?;
    let start = usize::try_from(off).ok()?;
    let stop = usize::try_from(off.checked_add(len)?).ok()?;
    map.file().get(start..stop)
}
