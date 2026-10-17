//! Entry points: `e_entry`, `DT_INIT`, `DT_FINI` and the init, fini and preinit arrays.
//!
//! The arrays come from the dynamic table. A file without these dynamic entries uses the
//! `SHT_INIT_ARRAY`, `SHT_FINI_ARRAY` and `SHT_PREINIT_ARRAY` sections. An array slot with
//! an `R_X86_64_RELATIVE` relocation takes the addend. Values 0 and all ones are not
//! entry points.

use std::collections::BTreeMap;

use super::consts::{
    DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ,
    DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, R_X86_64_RELATIVE, SHT_FINI_ARRAY, SHT_INIT_ARRAY,
    SHT_PREINIT_ARRAY,
};
use super::dynamic::Dyn;
use super::view::{Cx, Fields, entry, va_bytes};
use crate::binary::{Entry, EntryKind, Reloc, RelocForm, RelocType, Section, SectionKind};
use crate::memmap::MemoryMap;

/// The arrays: dynamic tags, section type and entry kind.
const ARRAYS: [(u64, u64, u32, EntryKind); 3] = [
    (
        DT_INIT_ARRAY,
        DT_INIT_ARRAYSZ,
        SHT_INIT_ARRAY,
        EntryKind::InitArray,
    ),
    (
        DT_FINI_ARRAY,
        DT_FINI_ARRAYSZ,
        SHT_FINI_ARRAY,
        EntryKind::FiniArray,
    ),
    (
        DT_PREINIT_ARRAY,
        DT_PREINIT_ARRAYSZ,
        SHT_PREINIT_ARRAY,
        EntryKind::PreinitArray,
    ),
];

/// Reads the slots of one array at `va`.
fn slots(
    cx: &Cx<'_>,
    map: &MemoryMap,
    va: u64,
    size: u64,
    relative: &BTreeMap<u64, i64>,
    kind: EntryKind,
    out: &mut Vec<Entry>,
) {
    let Some((bytes, _)) = va_bytes(map, cx.bytes, va, size) else {
        return;
    };
    for i in 0..bytes.len() / 8 {
        let Some(raw) = entry(bytes, i, 8) else {
            break;
        };
        let slot = u64::try_from(i)
            .ok()
            .and_then(|i| i.checked_mul(8))
            .and_then(|o| va.checked_add(o));
        let file_value = Fields::new(raw).u64();
        let value = slot
            .and_then(|s| relative.get(&s))
            .map_or(file_value, |a| a.cast_unsigned());
        if value != 0 && value != u64::MAX {
            out.push(Entry { addr: value, kind });
        }
    }
}

/// Gives the entry points in address order, then kind order.
pub(crate) fn collect(
    cx: &Cx<'_>,
    map: &MemoryMap,
    e_entry: u64,
    d: &Dyn,
    sections: &[Section],
    relocs: &[Reloc],
) -> Vec<Entry> {
    let mut out = Vec::new();
    if e_entry != 0 {
        out.push(Entry {
            addr: e_entry,
            kind: EntryKind::Entry,
        });
    }
    for (tag, kind) in [(DT_INIT, EntryKind::Init), (DT_FINI, EntryKind::Fini)] {
        if let Some(addr) = d.get(tag).filter(|a| *a != 0) {
            out.push(Entry { addr, kind });
        }
    }
    let relative: BTreeMap<u64, i64> = relocs
        .iter()
        .filter(|r| {
            r.form == RelocForm::Rela && r.kind == RelocType(R_X86_64_RELATIVE) && r.sym.is_none()
        })
        .map(|r| (r.offset, r.addend))
        .collect();
    for (tag, size_tag, sh_type, kind) in ARRAYS {
        let place = match (d.get(tag), d.get(size_tag)) {
            (Some(va), Some(size)) => Some((va, size)),
            _ => sections
                .iter()
                .find(|s| s.kind == SectionKind::Elf(sh_type))
                .map(|s| (s.addr, s.size)),
        };
        if let Some((va, size)) = place {
            slots(cx, map, va, size, &relative, kind, &mut out);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}
