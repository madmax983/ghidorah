//! REL, RELA and RELR tables (design Section 4.3).
//!
//! With section headers, each `SHT_REL`, `SHT_RELA` and `SHT_RELR` section gives its
//! entries in section order. Without them, the dynamic view gives the tables of `DT_REL`,
//! `DT_RELA`, `DT_RELR` and `DT_JMPREL` in this order, as `readelf -D -r` does. The loader
//! reads no table twice: it skips a table inside an earlier table.
//!
//! - `r_info` splits into `sym = info >> 32` and `type = info & 0xffff_ffff`.
//! - An even RELR entry is an address. An odd entry is a 63-bit bitmap of the next places.
//!   Each place is an implicit `R_X86_64_RELATIVE`.
//! - An x86-64 type outside the known set gives `E_UNSUPPORTED_RELOC` once per type.

use std::collections::BTreeSet;

use ghidorah_base::{DiagCode, Range};

use super::consts::{
    DT_JMPREL, DT_PLTREL, DT_PLTRELSZ, DT_REL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELENT, DT_RELR,
    DT_RELRENT, DT_RELRSZ, DT_RELSZ, R_X86_64_RELATIVE, REL_SIZE, RELA_SIZE, RELR_SIZE, SHT_REL,
    SHT_RELA, SHT_RELR, SHT_SYMTAB,
};
use super::dynamic::Dyn;
use super::sections::bytes_of;
use super::view::{Cx, Fields, entry, va_bytes};
use crate::binary::{Reloc, RelocForm, RelocSource, RelocType, Section, SectionKind, SymTable};
use crate::diag::Diagnostic;
use crate::memmap::MemoryMap;

/// The state of one relocation pass.
struct Out {
    relocs: Vec<Reloc>,
    x86_64: bool,
    told_types: BTreeSet<u32>,
}

impl Out {
    /// Checks the type of `r` and keeps it.
    fn push(&mut self, cx: &mut Cx<'_>, r: Reloc, path: &str) {
        if self.x86_64 && r.kind.x86_64_name().is_none() && self.told_types.insert(r.kind.0) {
            cx.diag(
                Diagnostic::new(DiagCode::UnsupportedReloc, path)
                    .at(r.offset)
                    .have(u64::from(r.kind.0)),
            );
        }
        self.relocs.push(r);
    }
}

/// The shape of one table.
#[derive(Clone, Copy)]
struct Shape {
    form: RelocForm,
    source: RelocSource,
    sym_table: SymTable,
}

const fn entsize(form: RelocForm) -> u64 {
    match form {
        RelocForm::Rel => REL_SIZE,
        RelocForm::Rela => RELA_SIZE,
        RelocForm::Relr => RELR_SIZE,
    }
}

/// Parses the entries of one table.
fn table(cx: &mut Cx<'_>, out: &mut Out, bytes: &[u8], shape: Shape, path: &str) {
    let size = entsize(shape.form);
    let step = usize::try_from(size).unwrap_or(usize::MAX);
    let count = u64::try_from(bytes.len().checked_div(step).unwrap_or(0)).unwrap_or(u64::MAX);
    if shape.form == RelocForm::Relr {
        relr(cx, out, bytes, count, shape, path);
        return;
    }
    let room = cx.budget.take_relocs(count, path, &mut cx.diags);
    let room = usize::try_from(room).unwrap_or(usize::MAX);
    out.relocs.reserve(room);
    for i in 0..room {
        let Some(raw) = entry(bytes, i, step) else {
            break;
        };
        let mut f = Fields::new(raw);
        let offset = f.u64();
        let info = f.u64();
        let addend = if shape.form == RelocForm::Rela {
            f.u64().cast_signed()
        } else {
            0
        };
        let sym = u32::try_from(info >> 32).unwrap_or(u32::MAX);
        let r = Reloc {
            offset,
            kind: RelocType(u32::try_from(info & 0xffff_ffff).unwrap_or(u32::MAX)),
            sym: (sym != 0).then_some(sym),
            sym_table: shape.sym_table,
            addend,
            form: shape.form,
            source: shape.source,
        };
        out.push(cx, r, path);
    }
}

/// Expands a RELR table into relocations.
fn relr(cx: &mut Cx<'_>, out: &mut Out, bytes: &[u8], count: u64, shape: Shape, path: &str) {
    let mut place = 0u64;
    let step = usize::try_from(RELR_SIZE).unwrap_or(usize::MAX);
    let emit = |cx: &mut Cx<'_>, out: &mut Out, at: u64| -> bool {
        if cx.budget.take_relocs(1, path, &mut cx.diags) == 0 {
            return false;
        }
        let r = Reloc {
            offset: at,
            kind: RelocType(R_X86_64_RELATIVE),
            sym: None,
            sym_table: shape.sym_table,
            addend: 0,
            form: RelocForm::Relr,
            source: shape.source,
        };
        out.push(cx, r, path);
        true
    };
    for i in 0..usize::try_from(count).unwrap_or(usize::MAX) {
        let Some(raw) = entry(bytes, i, step) else {
            break;
        };
        let word = Fields::new(raw).u64();
        if word & 1 == 0 {
            if !emit(cx, out, word) {
                return;
            }
            place = word.saturating_add(RELR_SIZE);
            continue;
        }
        let mut bits = word >> 1;
        let mut at = place;
        while bits != 0 {
            if bits & 1 == 1 && !emit(cx, out, at) {
                return;
            }
            bits >>= 1;
            at = at.saturating_add(RELR_SIZE);
        }
        place = place.saturating_add(63 * RELR_SIZE);
    }
}

/// Reads the relocation sections.
fn from_sections(cx: &mut Cx<'_>, out: &mut Out, sections: &[Section]) {
    for s in sections {
        let form = match s.kind {
            SectionKind::Elf(SHT_REL) => RelocForm::Rel,
            SectionKind::Elf(SHT_RELA) => RelocForm::Rela,
            SectionKind::Elf(SHT_RELR) => RelocForm::Relr,
            _ => continue,
        };
        let path = format!("elf.shdr[{}]", s.index);
        if s.entsize != entsize(form) {
            cx.diag(
                Diagnostic::new(DiagCode::BadEntsize, format!("{path}.sh_entsize"))
                    .need(entsize(form))
                    .have(s.entsize),
            );
            continue;
        }
        let Some(bytes) = bytes_of(cx, s) else {
            continue;
        };
        let linked = usize::try_from(s.link).ok().and_then(|i| sections.get(i));
        let sym_table = match linked.map(|l| l.kind) {
            Some(SectionKind::Elf(SHT_SYMTAB)) => SymTable::Symtab,
            _ => SymTable::Dynsym,
        };
        let shape = Shape {
            form,
            source: RelocSource::Section(s.index),
            sym_table,
        };
        table(cx, out, bytes, shape, &path);
    }
}

/// Gives the entry size of a dynamic table, or `None` with a diagnostic.
fn dyn_entsize(cx: &mut Cx<'_>, d: &Dyn, tag: u64, form: RelocForm, path: &str) -> Option<()> {
    let want = entsize(form);
    match d.get(tag) {
        None => Some(()),
        Some(v) if v == want => Some(()),
        Some(0) => {
            cx.diag(
                Diagnostic::new(DiagCode::Loop, path)
                    .need(want)
                    .have(0)
                    .hint("an entry size of 0 does not advance"),
            );
            None
        }
        Some(v) => {
            cx.diag(
                Diagnostic::new(DiagCode::BadEntsize, path)
                    .need(want)
                    .have(v),
            );
            None
        }
    }
}

/// Reads the tables of the dynamic view.
fn from_dynamic(cx: &mut Cx<'_>, out: &mut Out, map: &MemoryMap, d: &Dyn) {
    let jmprel_form = match d.get(DT_PLTREL) {
        Some(DT_REL) => Some(RelocForm::Rel),
        Some(DT_RELA) | None => Some(RelocForm::Rela),
        Some(other) => {
            cx.diag(
                Diagnostic::new(DiagCode::BadEntsize, "elf.dynamic.DT_PLTREL")
                    .have(other)
                    .hint("DT_PLTREL is not DT_REL or DT_RELA"),
            );
            None
        }
    };
    let ent_tag = |form| match form {
        RelocForm::Rel => (DT_RELENT, "elf.dynamic.DT_RELENT"),
        RelocForm::Rela => (DT_RELAENT, "elf.dynamic.DT_RELAENT"),
        RelocForm::Relr => (DT_RELRENT, "elf.dynamic.DT_RELRENT"),
    };
    let mut tables = vec![
        (DT_REL, DT_RELSZ, RelocForm::Rel, RelocSource::DynRel),
        (DT_RELA, DT_RELASZ, RelocForm::Rela, RelocSource::DynRela),
        (DT_RELR, DT_RELRSZ, RelocForm::Relr, RelocSource::DynRelr),
    ];
    if let Some(form) = jmprel_form {
        tables.push((DT_JMPREL, DT_PLTRELSZ, form, RelocSource::DynPlt));
    }
    let mut seen: Vec<Range> = Vec::new();
    for (tag, size_tag, form, source) in tables {
        let (Some(va), Some(size)) = (d.get(tag), d.get(size_tag)) else {
            continue;
        };
        let Some(range) = Range::with_len(va, size) else {
            continue;
        };
        if seen
            .iter()
            .any(|r| r.first <= range.first && range.last <= r.last)
        {
            continue;
        }
        seen.push(range);
        let path = format!("elf.dynamic.{}", label(source));
        let (ent, ent_path) = ent_tag(form);
        if dyn_entsize(cx, d, ent, form, ent_path).is_none() {
            continue;
        }
        let Some((bytes, cut)) = va_bytes(map, cx.bytes, va, size) else {
            cx.diag(Diagnostic::new(DiagCode::Oob, path).at(va).need(size));
            continue;
        };
        if cut {
            cx.diag(
                Diagnostic::new(DiagCode::Oob, path.clone())
                    .at(va)
                    .need(size)
                    .have(u64::try_from(bytes.len()).unwrap_or(0)),
            );
        }
        let shape = Shape {
            form,
            source,
            sym_table: SymTable::Dynsym,
        };
        table(cx, out, bytes, shape, &path);
    }
}

const fn label(source: RelocSource) -> &'static str {
    match source {
        RelocSource::DynRel => "DT_REL",
        RelocSource::DynRelr => "DT_RELR",
        RelocSource::DynPlt => "DT_JMPREL",
        RelocSource::DynRela | RelocSource::Section(_) => "DT_RELA",
    }
}

/// Reads the relocations of the file.
pub(crate) fn load(
    cx: &mut Cx<'_>,
    map: &MemoryMap,
    sections: &[Section],
    d: &Dyn,
    x86_64: bool,
) -> Vec<Reloc> {
    let mut out = Out {
        relocs: Vec::new(),
        x86_64,
        told_types: BTreeSet::new(),
    };
    if sections.is_empty() {
        from_dynamic(cx, &mut out, map, d);
    } else {
        from_sections(cx, &mut out, sections);
    }
    out.relocs
}
