//! Exports and forwarders (design Section 4.12).
//!
//! | Rule | Result |
//! |---|---|
//! | `NumberOfFunctions`, `NumberOfNames` | clamped to the export limit and to the bytes left, before any allocation |
//! | ordinal | the index in the export address table plus `Base` |
//! | an address inside the directory range | a forwarder string; the export has no address |
//! | an address of 0 | an unused slot: no export |
//! | a slot with names | one export for each name, in name table order |
//!
//! The loader never follows a forwarder, so a forwarder cycle cannot loop. The DLL name of the
//! directory goes to `identity.soname`. Each named export with an address gets a symbol (table
//! `Export`).

use std::collections::BTreeMap;

use ghidorah_base::{BinText, DiagCode};

use super::Px;
use crate::binary::{Binary, Export, Sym, SymBind, SymKind, SymTable, SymVis};
use crate::diag::Diagnostic;

/// Reads the little-endian `u32` at `i` of a table.
fn word(table: &[u8], i: usize) -> u32 {
    let at = i.saturating_mul(4);
    table
        .get(at..at.saturating_add(4))
        .and_then(|w| <[u8; 4]>::try_from(w).ok())
        .map_or(0, u32::from_le_bytes)
}

/// Reads the little-endian `u16` at `i` of a table.
fn half(table: &[u8], i: usize) -> u16 {
    let at = i.saturating_mul(2);
    table
        .get(at..at.saturating_add(2))
        .and_then(|w| <[u8; 2]>::try_from(w).ok())
        .map_or(0, u16::from_le_bytes)
}

/// Clamps a table count to the export limit and to the mapped bytes at `rva`.
fn clamp(px: &mut Px<'_>, count: u32, rva: u32, entsize: u64, path: &str) -> u64 {
    let mut n = u64::from(count);
    let limit = px.budget.limits.pe_exports;
    if n > limit {
        px.diag(Diagnostic::new(DiagCode::Limit, path).need(n).have(limit));
        n = limit;
    }
    let left = px
        .base
        .checked_add(u64::from(rva))
        .map_or(0, |va| px.avail(va));
    let fit = left.checked_div(entsize).unwrap_or(0);
    if n > fit {
        px.diag(
            Diagnostic::new(DiagCode::Oob, path)
                .at(u64::from(rva))
                .need(n.saturating_mul(entsize))
                .have(left),
        );
        n = fit;
    }
    n
}

/// Reads a table of `n` entries of `entsize` bytes at `rva`.
fn table(px: &mut Px<'_>, rva: u32, n: u64, entsize: u64, path: &str) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    px.read(rva, n.saturating_mul(entsize), path)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

/// Reads the export directory at `rva` with `size` bytes into `b`.
pub(crate) fn load(px: &mut Px<'_>, rva: u32, size: u32, b: &mut Binary) {
    let path = "pe.export";
    let Some(dir) = px.read(rva, 40, path) else {
        return;
    };
    let dir = dir.into_owned();
    let field = |i: usize| word(dir.get(12..).unwrap_or_default(), i);
    let (name, base, functions, names) = (field(0), field(1), field(2), field(3));
    let (eat_rva, names_rva, ords_rva) = (field(4), field(5), field(6));
    if name != 0 {
        b.identity.soname = px.cstr(name, "pe.export.Name");
    }
    let nf = clamp(px, functions, eat_rva, 4, "pe.export.NumberOfFunctions");
    let nn = clamp(px, names, names_rva, 4, "pe.export.NumberOfNames");
    let nn = nn.min(clamp(
        px,
        names,
        ords_rva,
        2,
        "pe.export.AddressOfNameOrdinals",
    ));
    let eat = table(px, eat_rva, nf, 4, "pe.export.AddressOfFunctions");
    let name_ptrs = table(px, names_rva, nn, 4, "pe.export.AddressOfNames");
    let ords = table(px, ords_rva, nn, 2, "pe.export.AddressOfNameOrdinals");
    let mut by_index: BTreeMap<u16, Vec<BinText>> = BTreeMap::new();
    for i in 0..usize::try_from(nn).unwrap_or(0) {
        let index = half(&ords, i);
        if let Some(text) = px.cstr(word(&name_ptrs, i), "pe.export.name") {
            by_index.entry(index).or_default().push(text);
        }
    }
    let end = rva.saturating_add(size);
    for i in 0..usize::try_from(nf).unwrap_or(0) {
        let target = word(&eat, i);
        if target == 0 {
            continue;
        }
        let ordinal = u32::try_from(i).ok().and_then(|k| k.checked_add(base));
        let (addr, forwarder) = if (rva..end).contains(&target) {
            (None, px.cstr(target, "pe.export.forwarder"))
        } else {
            (px.va(target, "pe.export.address"), None)
        };
        let names = u16::try_from(i)
            .ok()
            .and_then(|k| by_index.remove(&k))
            .unwrap_or_default();
        let list: Vec<Option<BinText>> = if names.is_empty() {
            vec![None]
        } else {
            names.into_iter().map(Some).collect()
        };
        for name in list {
            if let (Some(n), Some(a)) = (&name, addr) {
                add_symbol(px, b, n, a);
            }
            b.exports.push(Export {
                name,
                ordinal,
                addr,
                forwarder: forwarder.clone(),
            });
        }
    }
}

/// Adds the symbol of a named export with an address.
fn add_symbol(px: &Px<'_>, b: &mut Binary, name: &BinText, addr: u64) {
    let kind = if px.is_exec(addr) {
        SymKind::Func
    } else {
        SymKind::Object
    };
    let index = u32::try_from(b.symbols.len()).unwrap_or(u32::MAX);
    b.symbols.push(Sym {
        index,
        name: name.clone(),
        version: None,
        addr,
        size: 0,
        kind,
        bind: SymBind::Global,
        vis: SymVis::Default,
        shndx: 0,
        table: SymTable::Export,
    });
}
