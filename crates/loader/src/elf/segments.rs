//! Program headers and the memory map of `PT_LOAD` (design Sections 3.3 and 4.3).
//!
//! Each `PT_LOAD` with a memory size gives one region. Bytes in `[p_filesz, p_memsz)`
//! read as zero. A later `PT_LOAD` replaces the overlapped part of an earlier one, as the
//! kernel maps them, with `E_OVERLAP`.

use std::sync::Arc;

use ghidorah_base::{DiagCode, Range};

use super::consts::{PHDR_SIZE, PT_LOAD};
use super::header::Header;
use super::view::{Cx, Fields, entry};
use crate::binary::{Segment, SegmentKind};
use crate::diag::Diagnostic;
use crate::limits::clamp_count;
use crate::memmap::{MemoryMap, Perms, Region, RegionSource};

/// Parses `phnum` program headers at `e_phoff`.
pub(crate) fn parse(cx: &mut Cx<'_>, h: &Header, phnum: u64) -> Vec<Segment> {
    if phnum == 0 {
        return Vec::new();
    }
    let entsize = u64::from(h.phentsize);
    if entsize < PHDR_SIZE {
        cx.diag(
            Diagnostic::new(DiagCode::BadEntsize, "elf.ehdr.e_phentsize")
                .need(PHDR_SIZE)
                .have(entsize),
        );
        return Vec::new();
    }
    let size = phnum.saturating_mul(entsize);
    let Some(table) = cx.file_range(h.phoff, size, "elf.phdr") else {
        return Vec::new();
    };
    let avail = u64::try_from(table.len()).unwrap_or(0);
    let limit = cx.budget.limits.program_headers;
    // The file range gave `E_OOB` for a cut table, so the clamp only checks the limit.
    let n = clamp_count(phnum, entsize, u64::MAX, limit, "elf.phdr", &mut cx.diags);
    let fit = usize::try_from(avail.checked_div(entsize).unwrap_or(0)).unwrap_or(usize::MAX);
    let step = usize::try_from(entsize).unwrap_or(usize::MAX);
    let mut out = Vec::with_capacity(n.min(fit));
    for i in 0..n.min(fit) {
        let Some(raw) = entry(table, i, step) else {
            break;
        };
        out.push(one(cx, raw, i));
    }
    out
}

fn one(cx: &mut Cx<'_>, raw: &[u8], i: usize) -> Segment {
    let mut f = Fields::new(raw);
    let p_type = f.u32();
    let flags = f.u32();
    let file_off = f.u64();
    let vaddr = f.u64();
    let paddr = f.u64();
    let file_size = f.u64();
    let mem_size = f.u64();
    let align = f.u64();
    let va = if mem_size == 0 {
        None
    } else {
        let va = Range::with_len(vaddr, mem_size);
        if va.is_none() {
            cx.diag(
                Diagnostic::new(DiagCode::Overflow, format!("elf.phdr[{i}].p_vaddr"))
                    .at(vaddr)
                    .need(mem_size),
            );
        }
        va
    };
    Segment {
        index: u32::try_from(i).unwrap_or(u32::MAX),
        kind: SegmentKind::Elf(p_type),
        va,
        vaddr,
        paddr,
        file_off,
        file_size,
        mem_size,
        perms: Perms::from_elf(flags),
        flags,
        align,
    }
}

/// Builds the memory map from the `PT_LOAD` segments.
pub(crate) fn map(cx: &mut Cx<'_>, file: Arc<[u8]>, segments: &[Segment]) -> MemoryMap {
    let len = cx.len();
    let mut regions = Vec::new();
    let mut owners = Vec::new();
    for s in segments
        .iter()
        .filter(|s| s.kind == SegmentKind::Elf(PT_LOAD))
    {
        let Some(va) = s.va else {
            continue;
        };
        if s.file_size > s.mem_size {
            cx.diag(
                Diagnostic::new(DiagCode::Oob, format!("elf.phdr[{}].p_filesz", s.index))
                    .need(s.file_size)
                    .have(s.mem_size),
            );
        }
        let in_file = s.file_off.checked_add(s.file_size.min(s.mem_size));
        if in_file.is_none_or(|end| end > len) {
            cx.diag(
                Diagnostic::new(DiagCode::Oob, format!("elf.phdr[{}].p_offset", s.index))
                    .at(s.file_off)
                    .need(s.file_size)
                    .have(len.saturating_sub(s.file_off)),
            );
        }
        regions.push(Region {
            name: format!("seg:{}", s.index),
            va,
            file_off: s.file_off,
            file_size: s.file_size.min(s.mem_size),
            perms: s.perms,
            source: RegionSource::ElfSegment(s.index),
        });
        owners.push(s.index);
    }
    let mut map = MemoryMap::new(file);
    for i in map.map_all(regions) {
        let index = owners.get(i).copied().unwrap_or(u32::MAX);
        cx.diag(Diagnostic::new(
            DiagCode::Overlap,
            format!("elf.phdr[{index}]"),
        ));
    }
    map
}

/// Gives the image base: the page of the lowest `PT_LOAD` address.
pub(crate) fn image_base(segments: &[Segment]) -> u64 {
    segments
        .iter()
        .filter(|s| s.kind == SegmentKind::Elf(PT_LOAD) && s.va.is_some())
        .map(|s| s.vaddr & !0xfff)
        .min()
        .unwrap_or(0)
}
