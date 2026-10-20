//! The section table, the loader-faithful regions and the segments (design Section 4.10).
//!
//! | Value | Rule |
//! |---|---|
//! | headers | RVAs below `SizeOfHeaders` map to the same file offsets, region `headers` with `READ` |
//! | `vsize` | `VirtualSize`; 0 means `SizeOfRawData`; 0 for both maps nothing |
//! | `file_off` | `PointerToRawData`, rounded down to a multiple of 0x200 when `FileAlignment` is at least 0x200 (the `pefile` rule) |
//! | `file_size` | `min(SizeOfRawData, vsize)`, 0 for `CNT_UNINITIALIZED_DATA`, cut at the end of the file |
//! | overlap | a later section replaces the overlapped part of an earlier region, with `E_OVERLAP` |
//!
//! Each [`Section`] keeps the raw header values: `size` is `VirtualSize`, `entsize` is
//! `SizeOfRawData`, `file_off` is `PointerToRawData` and `flags` is `Characteristics`.

use std::sync::Arc;

use ghidorah_base::{BinText, DiagCode, Limits, Range};
use ghidorah_kernel::{Endian, Reader};

use super::headers::Headers;
use crate::binary::{Section, SectionKind, Segment, SegmentKind};
use crate::diag::{Diagnostic, Diags};
use crate::limits::clamp_count;
use crate::memmap::{MemoryMap, Perms, Region, RegionSource};

/// The size of one section header.
const SHDR_SIZE: u64 = 40;

/// `IMAGE_SCN_CNT_UNINITIALIZED_DATA`.
pub(crate) const SCN_UNINITIALIZED: u64 = 0x80;
/// `IMAGE_SCN_MEM_EXECUTE`.
pub(crate) const SCN_EXECUTE: u64 = 0x2000_0000;
/// `IMAGE_SCN_MEM_READ`.
pub(crate) const SCN_READ: u64 = 0x4000_0000;
/// `IMAGE_SCN_MEM_WRITE`.
pub(crate) const SCN_WRITE: u64 = 0x8000_0000;

/// The file alignment that the Windows loader uses for `PointerToRawData`.
const RAW_ALIGN: u64 = 0x200;

/// Gives the file offset of the raw data of a section. With a `FileAlignment` of 0x200 or
/// more, the offset rounds down to a multiple of 0x200. A low-alignment image maps flat.
const fn raw_offset(raw_ptr: u64, file_align: u64) -> u64 {
    if file_align >= RAW_ALIGN {
        raw_ptr & !RAW_ALIGN.saturating_sub(1)
    } else {
        raw_ptr
    }
}

/// Gives the access bits of section `Characteristics`.
fn perms(flags: u64) -> Perms {
    let mut out = Perms::NONE;
    for (bit, perm) in [
        (SCN_READ, Perms::READ),
        (SCN_WRITE, Perms::WRITE),
        (SCN_EXECUTE, Perms::EXECUTE),
    ] {
        if flags & bit != 0 {
            out = out.union(perm);
        }
    }
    out
}

/// Parses the section table after the optional header.
pub(crate) fn parse(bytes: &[u8], h: &Headers, limits: &Limits, diags: &mut Diags) -> Vec<Section> {
    let start = h.opt_off.saturating_add(u64::from(h.opt_size));
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let avail = len.saturating_sub(start);
    let n = clamp_count(
        u64::from(h.sections),
        SHDR_SIZE,
        avail,
        limits.sections,
        "pe.shdr",
        diags,
    );
    let table = usize::try_from(start)
        .ok()
        .and_then(|s| bytes.get(s..))
        .unwrap_or_default();
    let mut out = Vec::with_capacity(n);
    for (i, raw) in table
        .chunks_exact(usize::try_from(SHDR_SIZE).unwrap_or(usize::MAX))
        .take(n)
        .enumerate()
    {
        out.push(one(raw, i, h.image_base, diags));
    }
    out
}

/// Parses one section header.
fn one(raw: &[u8], i: usize, base: u64, diags: &mut Diags) -> Section {
    let name_bytes = raw.get(..8).unwrap_or_default();
    let name_len = name_bytes.iter().position(|b| *b == 0).unwrap_or(8);
    let name = BinText::new(name_bytes.get(..name_len).unwrap_or_default());
    let mut r = Reader::new(raw.get(8..).unwrap_or_default(), Endian::Little);
    let vsize = r.u32().unwrap_or(0);
    let rva = r.u32().unwrap_or(0);
    let raw_size = r.u32().unwrap_or(0);
    let raw_ptr = r.u32().unwrap_or(0);
    let _ = r.skip(12);
    let flags = r.u32().unwrap_or(0);
    let mem = if vsize == 0 { raw_size } else { vsize };
    let addr = base.checked_add(u64::from(rva));
    let va = match addr {
        Some(a) if mem > 0 => {
            let range = Range::with_len(a, u64::from(mem));
            if range.is_none() {
                diags.push(
                    Diagnostic::new(DiagCode::Overflow, format!("pe.shdr[{i}].VirtualAddress"))
                        .at(a)
                        .need(u64::from(mem)),
                );
            }
            range
        }
        Some(_) => None,
        None => {
            diags.push(
                Diagnostic::new(DiagCode::Overflow, format!("pe.shdr[{i}].VirtualAddress"))
                    .at(u64::from(rva))
                    .need(base),
            );
            None
        }
    };
    Section {
        index: u32::try_from(i).unwrap_or(u32::MAX),
        name,
        kind: SectionKind::Pe,
        va,
        addr: addr.unwrap_or_else(|| u64::from(rva)),
        file_off: u64::from(raw_ptr),
        size: u64::from(vsize),
        flags: u64::from(flags),
        link: 0,
        info: 0,
        align: 0,
        entsize: u64::from(raw_size),
    }
}

/// Gives the region of a section, and adds `E_OOB` when its file part leaves the file.
fn region(s: &Section, h: &Headers, len: u64, diags: &mut Diags) -> Option<Region> {
    let va = s.va?;
    let mem = u64::try_from(va.len()).unwrap_or(u64::MAX);
    let file_off = raw_offset(s.file_off, u64::from(h.file_alignment));
    let file_size = if s.flags & SCN_UNINITIALIZED != 0 {
        0
    } else {
        s.entsize.min(mem)
    };
    let end = file_off.checked_add(file_size);
    if file_size > 0 && end.is_none_or(|e| e > len) {
        diags.push(
            Diagnostic::new(
                DiagCode::Oob,
                format!("pe.shdr[{}].PointerToRawData", s.index),
            )
            .at(file_off)
            .need(file_size)
            .have(len.saturating_sub(file_off)),
        );
    }
    Some(Region {
        name: s.name.as_str().unwrap_or("section").to_owned(),
        va,
        file_off,
        file_size,
        perms: perms(s.flags),
        source: RegionSource::PeSection(s.index),
    })
}

/// Gives the segment of a region.
fn segment(index: u32, kind: SegmentKind, r: &Region, flags: u32, align: u64) -> Segment {
    let size = u64::try_from(r.va.len()).unwrap_or(u64::MAX);
    Segment {
        index,
        kind,
        va: Some(r.va),
        vaddr: r.va.first,
        paddr: r.va.first,
        file_off: r.file_off,
        file_size: r.file_size,
        mem_size: size,
        perms: r.perms,
        flags,
        align,
    }
}

/// Builds the memory map and the segments: the headers, then the sections in table order.
pub(crate) fn map(
    file: Arc<[u8]>,
    h: &Headers,
    sections: &[Section],
    diags: &mut Diags,
) -> (MemoryMap, Vec<Segment>) {
    let len = u64::try_from(file.len()).unwrap_or(u64::MAX);
    let align = u64::from(h.section_alignment);
    let mut regions: Vec<Region> = Vec::new();
    let mut owners: Vec<Option<u32>> = Vec::new();
    let mut segments = Vec::new();
    let headers = Range::with_len(h.image_base, u64::from(h.header_size));
    if let Some(va) = headers.filter(|_| h.header_size > 0) {
        let r = Region {
            name: "headers".to_owned(),
            va,
            file_off: 0,
            file_size: u64::from(h.header_size).min(len),
            perms: Perms::READ,
            source: RegionSource::PeHeaders,
        };
        segments.push(segment(0, SegmentKind::PeHeaders, &r, 0, align));
        regions.push(r);
        owners.push(None);
    } else if h.header_size > 0 {
        diags.push(
            Diagnostic::new(DiagCode::Overflow, "pe.optional.SizeOfHeaders")
                .at(h.image_base)
                .need(u64::from(h.header_size)),
        );
    }
    for s in sections {
        let Some(r) = region(s, h, len, diags) else {
            continue;
        };
        let index = u32::try_from(segments.len()).unwrap_or(u32::MAX);
        let flags = u32::try_from(s.flags).unwrap_or(u32::MAX);
        segments.push(segment(index, SegmentKind::PeSection, &r, flags, align));
        regions.push(r);
        owners.push(Some(s.index));
    }
    let mut out = MemoryMap::new(file);
    for i in out.map_all(regions) {
        let index = owners.get(i).copied().flatten().unwrap_or(u32::MAX);
        diags.push(Diagnostic::new(
            DiagCode::Overlap,
            format!("pe.shdr[{index}]"),
        ));
    }
    (out, segments)
}
