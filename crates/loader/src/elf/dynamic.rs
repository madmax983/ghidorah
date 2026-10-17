//! The dynamic table and its strings (design Section 4.3).
//!
//! The table comes from `PT_DYNAMIC`, or from the first `SHT_DYNAMIC` section when the file
//! has no `PT_DYNAMIC`. The walk stops after the first `DT_NULL`, which the model keeps.
//! Addresses in the table read through the memory map, so the dynamic view works without
//! section headers.

use ghidorah_base::{BinText, DiagCode};

use super::consts::{
    DT_NEEDED, DT_NULL, DT_RPATH, DT_RUNPATH, DT_SONAME, DT_STRSZ, DT_STRTAB, DYN_SIZE, PT_DYNAMIC,
    SHT_DYNAMIC,
};
use super::sections::first_of;
use super::view::{Cx, Fields, StrTab, entry, va_bytes};
use crate::binary::{DynEntry, Section, Segment, SegmentKind};
use crate::diag::Diagnostic;
use crate::memmap::MemoryMap;

/// The dynamic entries of a file, with lookups.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Dyn {
    /// The entries up to the first `DT_NULL`.
    pub(crate) entries: Vec<DynEntry>,
}

impl Dyn {
    /// Gives the value of the first entry with `tag`.
    pub(crate) fn get(&self, tag: u64) -> Option<u64> {
        self.entries.iter().find(|e| e.tag == tag).map(|e| e.val)
    }
}

/// Reads the dynamic entries.
pub(crate) fn parse(cx: &mut Cx<'_>, segments: &[Segment], sections: &[Section]) -> Dyn {
    let place = segments
        .iter()
        .find(|s| s.kind == SegmentKind::Elf(PT_DYNAMIC))
        .map(|s| (s.file_off, s.file_size))
        .or_else(|| first_of(sections, SHT_DYNAMIC).map(|s| (s.file_off, s.size)));
    let Some((off, size)) = place else {
        return Dyn::default();
    };
    let Some(table) = cx.file_range(off, size, "elf.dynamic") else {
        return Dyn::default();
    };
    let step = usize::try_from(DYN_SIZE).unwrap_or(usize::MAX);
    let count = table.len().checked_div(step).unwrap_or(0);
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let Some(raw) = entry(table, i, step) else {
            break;
        };
        let mut f = Fields::new(raw);
        let e = DynEntry {
            tag: f.u64(),
            val: f.u64(),
        };
        entries.push(e);
        if e.tag == DT_NULL {
            return Dyn { entries };
        }
    }
    if !entries.is_empty() {
        cx.diag(
            Diagnostic::new(DiagCode::Oob, "elf.dynamic")
                .at(off)
                .have(size)
                .hint("the table has no DT_NULL entry"),
        );
    }
    Dyn { entries }
}

/// Gives the dynamic string table `DT_STRTAB` of `DT_STRSZ` bytes.
pub(crate) fn strtab<'a>(cx: &mut Cx<'a>, map: &MemoryMap, d: &Dyn) -> StrTab<'a> {
    let Some(va) = d.get(DT_STRTAB) else {
        return StrTab::none();
    };
    let size = d.get(DT_STRSZ).unwrap_or(u64::MAX);
    let Some((bytes, cut)) = va_bytes(map, cx.bytes, va, size) else {
        cx.diag(Diagnostic::new(DiagCode::Oob, "elf.dynamic.DT_STRTAB").at(va));
        return StrTab::none();
    };
    if cut && size != u64::MAX {
        cx.diag(
            Diagnostic::new(DiagCode::Oob, "elf.dynamic.DT_STRTAB")
                .at(va)
                .need(size)
                .have(u64::try_from(bytes.len()).unwrap_or(0)),
        );
    }
    StrTab::new(bytes, "elf.dynstr")
}

/// The strings that the dynamic table names.
pub(crate) struct DynStrings {
    /// The `DT_NEEDED` names in table order.
    pub(crate) needed: Vec<BinText>,
    /// `DT_SONAME`.
    pub(crate) soname: Option<BinText>,
    /// `DT_RPATH`.
    pub(crate) rpath: Option<BinText>,
    /// `DT_RUNPATH`.
    pub(crate) runpath: Option<BinText>,
}

/// Reads the library names and the search paths.
pub(crate) fn strings(cx: &mut Cx<'_>, d: &Dyn, strtab: &mut StrTab<'_>) -> DynStrings {
    let mut needed = Vec::new();
    for e in d.entries.iter().filter(|e| e.tag == DT_NEEDED) {
        needed.push(strtab.get(cx, e.val));
    }
    let mut one = |tag| d.get(tag).map(|off| strtab.get(cx, off));
    DynStrings {
        needed,
        soname: one(DT_SONAME),
        rpath: one(DT_RPATH),
        runpath: one(DT_RUNPATH),
    }
}
