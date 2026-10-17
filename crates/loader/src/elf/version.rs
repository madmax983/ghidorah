//! Symbol versions: `DT_VERSYM`, `DT_VERNEED` and `DT_VERDEF`.
//!
//! The rules follow `readelf`:
//!
//! - A `DT_VERSYM` index of 0 or 1 gives no version.
//! - A defined symbol takes the `DT_VERDEF` entry with its index, but not the base entry
//!   and not an entry whose name is the symbol name.
//! - Else the symbol takes the first `DT_VERNEED` aux entry whose `vna_other` equals the value.
//!
//! The walks follow `vn_next`, `vna_next` and `vd_next`. A next offset of 0 before the end
//! of the count does not advance, so it gives `E_LOOP` and stops the walk. The steps of one
//! walk stay below the table length in bytes, so a hostile count cannot make it long.

use std::collections::BTreeMap;

use ghidorah_base::DiagCode;

use super::consts::{
    DT_VERDEF, DT_VERDEFNUM, DT_VERNEED, DT_VERNEEDNUM, DT_VERSYM, SHN_UNDEF, VERSYM_HIDDEN,
};
use super::dynamic::Dyn;
use super::symbols::Table;
use super::view::{Cx, Fields, StrTab, entry, va_bytes};
use crate::binary::SymVersion;
use crate::diag::Diagnostic;
use crate::memmap::MemoryMap;

/// The version flag of the base definition.
const VER_FLG_BASE: u16 = 1;

/// Gives the bytes of a version table at `va`, up to the end of its region.
fn table<'a>(cx: &mut Cx<'a>, map: &MemoryMap, va: u64, path: &str) -> &'a [u8] {
    if let Some((bytes, _)) = va_bytes(map, cx.bytes, va, u64::MAX) {
        bytes
    } else {
        cx.diag(Diagnostic::new(DiagCode::Oob, path).at(va));
        &[]
    }
}

/// Gives `len` bytes of `table` at `off`.
fn at(table: &[u8], off: u64, len: usize) -> Option<&[u8]> {
    let start = usize::try_from(off).ok()?;
    table.get(start..start.checked_add(len)?)
}

/// A step counter with the cap of one walk.
struct Steps {
    left: usize,
    path: &'static str,
}

impl Steps {
    fn new(table: &[u8], path: &'static str) -> Self {
        Self {
            left: table.len(),
            path,
        }
    }

    /// Takes one step. At the cap, gives `E_LIMIT` and `false`.
    fn take(&mut self, cx: &mut Cx<'_>) -> bool {
        if let Some(left) = self.left.checked_sub(1) {
            self.left = left;
            true
        } else {
            cx.diag(Diagnostic::new(DiagCode::Limit, self.path).hint("the walk is too long"));
            false
        }
    }
}

/// Gives the next offset of a walk, or `None` with `E_LOOP` for a step of 0.
fn advance(cx: &mut Cx<'_>, path: &str, off: u64, next: u32) -> Option<u64> {
    if next == 0 {
        cx.diag(
            Diagnostic::new(DiagCode::Loop, path)
                .at(off)
                .hint("a next offset of 0 comes before the end of the count"),
        );
        return None;
    }
    Some(off.saturating_add(u64::from(next)))
}

/// Walks the aux entries of one `Verneed` entry into `out`.
fn need_aux(
    cx: &mut Cx<'_>,
    bytes: &[u8],
    mut off: u64,
    cnt: u16,
    steps: &mut Steps,
    out: &mut BTreeMap<u16, u32>,
) {
    for j in 0..cnt {
        if !steps.take(cx) {
            return;
        }
        let Some(raw) = at(bytes, off, 16) else {
            cx.diag(Diagnostic::new(DiagCode::Oob, "elf.verneed.aux").at(off));
            return;
        };
        let mut f = Fields::new(raw);
        let _hash = f.u32();
        let _flags = f.u16();
        let other = f.u16();
        let name = f.u32();
        let next = f.u32();
        out.entry(other).or_insert(name);
        if j.saturating_add(1) < cnt {
            match advance(cx, "elf.verneed.aux", off, next) {
                Some(n) => off = n,
                None => return,
            }
        }
    }
}

/// Walks `DT_VERNEED` and gives the name offset of each `vna_other` value.
fn needs(cx: &mut Cx<'_>, map: &MemoryMap, d: &Dyn) -> BTreeMap<u16, u32> {
    let mut out = BTreeMap::new();
    let (Some(va), Some(count)) = (d.get(DT_VERNEED), d.get(DT_VERNEEDNUM)) else {
        return out;
    };
    let bytes = table(cx, map, va, "elf.verneed");
    let mut steps = Steps::new(bytes, "elf.verneed");
    let mut off = 0u64;
    let mut i = 0u64;
    while i < count && steps.take(cx) {
        let Some(raw) = at(bytes, off, 16) else {
            cx.diag(Diagnostic::new(DiagCode::Oob, "elf.verneed").at(off));
            break;
        };
        let mut f = Fields::new(raw);
        let _version = f.u16();
        let cnt = f.u16();
        let _file = f.u32();
        let aux = f.u32();
        let next = f.u32();
        need_aux(
            cx,
            bytes,
            off.saturating_add(u64::from(aux)),
            cnt,
            &mut steps,
            &mut out,
        );
        i = i.saturating_add(1);
        if i < count {
            match advance(cx, "elf.verneed", off, next) {
                Some(n) => off = n,
                None => break,
            }
        }
    }
    out
}

/// Walks `DT_VERDEF` and gives the flags and the name offset of each index.
fn defs(cx: &mut Cx<'_>, map: &MemoryMap, d: &Dyn) -> BTreeMap<u16, (u16, u32)> {
    let mut out = BTreeMap::new();
    let (Some(va), Some(count)) = (d.get(DT_VERDEF), d.get(DT_VERDEFNUM)) else {
        return out;
    };
    let bytes = table(cx, map, va, "elf.verdef");
    let mut steps = Steps::new(bytes, "elf.verdef");
    let mut off = 0u64;
    let mut i = 0u64;
    while i < count && steps.take(cx) {
        let Some(raw) = at(bytes, off, 20) else {
            cx.diag(Diagnostic::new(DiagCode::Oob, "elf.verdef").at(off));
            break;
        };
        let mut f = Fields::new(raw);
        let _version = f.u16();
        let flags = f.u16();
        let ndx = f.u16();
        let _cnt = f.u16();
        let _hash = f.u32();
        let aux = f.u32();
        let next = f.u32();
        let aux_at = off.saturating_add(u64::from(aux));
        if let Some(a) = at(bytes, aux_at, 8) {
            out.entry(ndx)
                .or_insert_with(|| (flags, Fields::new(a).u32()));
        }
        i = i.saturating_add(1);
        if i < count {
            match advance(cx, "elf.verdef", off, next) {
                Some(n) => off = n,
                None => break,
            }
        }
    }
    out
}

/// Sets the versions of the `.dynsym` symbols.
pub(crate) fn apply(
    cx: &mut Cx<'_>,
    map: &MemoryMap,
    d: &Dyn,
    dynstr: &mut StrTab<'_>,
    table: &mut Table,
) {
    let Some(va) = d.get(DT_VERSYM) else {
        return;
    };
    let want = u64::try_from(table.syms.len())
        .unwrap_or(u64::MAX)
        .saturating_mul(2);
    let Some((versym, _)) = va_bytes(map, cx.bytes, va, want) else {
        cx.diag(Diagnostic::new(DiagCode::Oob, "elf.versym").at(va));
        return;
    };
    let needs = needs(cx, map, d);
    let defs = defs(cx, map, d);
    for (i, (sym, st_name)) in table.syms.iter_mut().zip(&table.names).enumerate() {
        let Some(v) = entry(versym, i, 2).map(|e| Fields::new(e).u16()) else {
            break;
        };
        let index = v & !VERSYM_HIDDEN;
        if index <= 1 {
            continue;
        }
        let hidden = v & VERSYM_HIDDEN != 0;
        if sym.shndx != SHN_UNDEF
            && let Some(&(flags, name)) = defs.get(&index)
        {
            if flags & VER_FLG_BASE == 0 && name != *st_name {
                sym.version = Some(SymVersion {
                    name: dynstr.get(cx, u64::from(name)),
                    index,
                    hidden,
                    needed: false,
                });
            }
            continue;
        }
        if let Some(&name) = needs.get(&v) {
            sym.version = Some(SymVersion {
                name: dynstr.get(cx, u64::from(name)),
                index: v,
                hidden,
                needed: true,
            });
        }
    }
}
