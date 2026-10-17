//! Symbol tables: `.symtab`, `.dynsym` and the `DT_SYMTAB` view (design Section 4.3).
//!
//! The loader reads the first `SHT_DYNSYM` and the first `SHT_SYMTAB` section in section
//! order. Without a `SHT_DYNSYM` section, the dynamic view gives `.dynsym` from
//! `DT_SYMTAB`, with the count of the hash tables. Without a hash table, the count is
//! the distance from `DT_SYMTAB` to `DT_STRTAB`. `SHN_XINDEX` reads `SHT_SYMTAB_SHNDX`.

use ghidorah_base::DiagCode;

use super::consts::{
    DT_STRTAB, DT_SYMENT, DT_SYMTAB, SHN_UNDEF, SHN_XINDEX, SHT_DYNSYM, SHT_SYMTAB,
    SHT_SYMTAB_SHNDX, SYM_SIZE,
};
use super::dynamic::Dyn;
use super::sections::bytes_of;
use super::view::{Cx, Fields, StrTab, entry, va_bytes};
use crate::binary::{Export, Section, SectionKind, Sym, SymBind, SymKind, SymTable, SymVis};
use crate::diag::Diagnostic;
use crate::limits::clamp_count;
use crate::memmap::MemoryMap;

/// One parsed table: the symbols and the raw `st_name` of each.
pub(crate) struct Table {
    /// The symbols in table order.
    pub(crate) syms: Vec<Sym>,
    /// The raw `st_name` values.
    pub(crate) names: Vec<u32>,
}

/// Parses `count` entries of `bytes` with `strtab` names.
fn entries(
    cx: &mut Cx<'_>,
    bytes: &[u8],
    count: usize,
    strtab: &mut StrTab<'_>,
    xindex: Option<&[u8]>,
    table: SymTable,
) -> Table {
    let step = usize::try_from(SYM_SIZE).unwrap_or(usize::MAX);
    let mut syms = Vec::with_capacity(count);
    let mut names = Vec::with_capacity(count);
    let mut told_xindex = false;
    for i in 0..count {
        let Some(raw) = entry(bytes, i, step) else {
            break;
        };
        let mut f = Fields::new(raw);
        let name = f.u32();
        let info = f.u8();
        let other = f.u8();
        let mut shndx = u32::from(f.u16());
        let addr = f.u64();
        let size = f.u64();
        if shndx == SHN_XINDEX {
            let resolved = xindex
                .and_then(|x| entry(x, i, 4))
                .map(|e| Fields::new(e).u32());
            match resolved {
                Some(v) => shndx = v,
                None if !told_xindex => {
                    told_xindex = true;
                    cx.diag(
                        Diagnostic::new(DiagCode::Oob, "elf.symtab_shndx")
                            .at(u64::try_from(i).unwrap_or(u64::MAX)),
                    );
                }
                None => {}
            }
        }
        syms.push(Sym {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            name: strtab.get(cx, u64::from(name)),
            version: None,
            addr,
            size,
            kind: SymKind::from_raw(info & 0xf),
            bind: SymBind::from_raw(info >> 4),
            vis: SymVis::from_other(other),
            shndx,
            table,
        });
        names.push(name);
    }
    Table { syms, names }
}

/// Parses the symbol table section `s`.
fn from_section(cx: &mut Cx<'_>, sections: &[Section], s: &Section, table: SymTable) -> Table {
    let empty = Table {
        syms: Vec::new(),
        names: Vec::new(),
    };
    let path = format!("elf.shdr[{}]", s.index);
    if s.entsize != SYM_SIZE {
        cx.diag(
            Diagnostic::new(DiagCode::BadEntsize, format!("{path}.sh_entsize"))
                .need(SYM_SIZE)
                .have(s.entsize),
        );
        return empty;
    }
    let Some(bytes) = bytes_of(cx, s) else {
        return empty;
    };
    // The file range gave `E_OOB` for a cut table, so the clamp only checks the limit.
    let limit = cx.budget.limits.symbols;
    let count = clamp_count(
        s.size / SYM_SIZE,
        SYM_SIZE,
        u64::MAX,
        limit,
        &path,
        &mut cx.diags,
    )
    .min(bytes.len() / 24);
    let link = usize::try_from(s.link).ok().and_then(|i| sections.get(i));
    let mut strtab = if let Some(t) = link {
        bytes_of(cx, t).map_or_else(StrTab::none, |b| {
            StrTab::new(b, format!("elf.shdr[{}]", t.index))
        })
    } else {
        cx.diag(
            Diagnostic::new(DiagCode::Oob, format!("{path}.sh_link"))
                .need(u64::from(s.link))
                .have(u64::try_from(sections.len()).unwrap_or(u64::MAX)),
        );
        StrTab::none()
    };
    let xindex = sections
        .iter()
        .find(|x| x.kind == SectionKind::Elf(SHT_SYMTAB_SHNDX) && x.link == s.index)
        .cloned();
    let xbytes = xindex.and_then(|x| bytes_of(cx, &x));
    entries(cx, bytes, count, &mut strtab, xbytes, table)
}

/// Parses `.dynsym` through `DT_SYMTAB`. `count` is the count of the hash tables.
fn from_dynamic(
    cx: &mut Cx<'_>,
    map: &MemoryMap,
    d: &Dyn,
    count: Option<u64>,
    strtab: &mut StrTab<'_>,
) -> Table {
    let empty = Table {
        syms: Vec::new(),
        names: Vec::new(),
    };
    let Some(va) = d.get(DT_SYMTAB) else {
        return empty;
    };
    let syment = d.get(DT_SYMENT).unwrap_or(SYM_SIZE);
    if syment == 0 {
        cx.diag(
            Diagnostic::new(DiagCode::Loop, "elf.dynamic.DT_SYMENT")
                .need(SYM_SIZE)
                .have(0),
        );
        return empty;
    }
    if syment != SYM_SIZE {
        cx.diag(
            Diagnostic::new(DiagCode::BadEntsize, "elf.dynamic.DT_SYMENT")
                .need(SYM_SIZE)
                .have(syment),
        );
        return empty;
    }
    let count = count
        .or_else(|| {
            let strtab_va = d.get(DT_STRTAB)?;
            strtab_va.checked_sub(va).map(|gap| gap / SYM_SIZE)
        })
        .unwrap_or(0);
    let want = count.saturating_mul(SYM_SIZE);
    let Some((bytes, cut)) = va_bytes(map, cx.bytes, va, want) else {
        cx.diag(Diagnostic::new(DiagCode::Oob, "elf.dynsym").at(va));
        return empty;
    };
    if cut {
        cx.diag(
            Diagnostic::new(DiagCode::Oob, "elf.dynsym")
                .at(va)
                .need(want)
                .have(u64::try_from(bytes.len()).unwrap_or(0)),
        );
    }
    let limit = cx.budget.limits.symbols;
    let n = clamp_count(
        count,
        SYM_SIZE,
        u64::MAX,
        limit,
        "elf.dynsym",
        &mut cx.diags,
    )
    .min(bytes.len() / 24);
    entries(cx, bytes, n, strtab, None, SymTable::Dynsym)
}

/// The symbol tables of a file.
pub(crate) struct Symbols {
    /// `.dynsym`, from its section or from the dynamic view.
    pub(crate) dynsym: Table,
    /// `.symtab`.
    pub(crate) symtab: Table,
    /// The section index of `.dynsym`, or `None` for the dynamic view.
    pub(crate) dynsym_section: Option<u32>,
}

/// Reads both symbol tables.
pub(crate) fn load(
    cx: &mut Cx<'_>,
    map: &MemoryMap,
    sections: &[Section],
    d: &Dyn,
    hash_count: Option<u64>,
    dynstr: &mut StrTab<'_>,
) -> Symbols {
    let find = |t| sections.iter().find(|s| s.kind == SectionKind::Elf(t));
    let (dynsym, dynsym_section) = match find(SHT_DYNSYM) {
        Some(s) => (
            from_section(cx, sections, s, SymTable::Dynsym),
            Some(s.index),
        ),
        None => (from_dynamic(cx, map, d, hash_count, dynstr), None),
    };
    let symtab = match find(SHT_SYMTAB) {
        Some(s) => from_section(cx, sections, s, SymTable::Symtab),
        None => Table {
            syms: Vec::new(),
            names: Vec::new(),
        },
    };
    Symbols {
        dynsym,
        symtab,
        dynsym_section,
    }
}

/// Gives the exports: the defined global, weak and unique `.dynsym` symbols.
pub(crate) fn exports(cx: &mut Cx<'_>, dynsym: &[Sym]) -> Vec<Export> {
    let mut out = Vec::new();
    for s in dynsym {
        let defined = s.shndx != SHN_UNDEF;
        let global = matches!(s.bind, SymBind::Global | SymBind::Weak | SymBind::Unique);
        let real = !matches!(s.kind, SymKind::Section | SymKind::File);
        let visible = matches!(s.vis, SymVis::Default | SymVis::Protected);
        if !(defined && global && real && visible) {
            continue;
        }
        out.push(Export {
            name: Some(cx.text(s.name.as_bytes(), "elf.exports")),
            ordinal: None,
            addr: Some(s.addr),
            forwarder: None,
        });
    }
    out
}
