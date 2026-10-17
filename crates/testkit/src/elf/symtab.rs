//! `.symtab`, `.strtab` and note sections.

use std::collections::BTreeMap;

use super::consts::{SHF_ALLOC, SHT_NOTE, STB_LOCAL, SYM64_SIZE};
use super::plan::{Ctx, Sect};
use super::write::{StrTab, align_up, p16, p32, p64, u32_of, u64_of, usize_of};
use super::{ElfBuilder, Note};

/// The result of the symbol table build.
pub(crate) struct SymbolTables {
    /// The bytes of `.symtab`.
    pub(crate) table: Vec<u8>,
    /// The bytes of `.strtab`.
    pub(crate) strings: Vec<u8>,
    /// The index of the first non-local symbol.
    pub(crate) first_global: u32,
}

/// Builds `.symtab` and `.strtab`: the null symbol, the local symbols, then the others.
pub(crate) fn symtab(b: &ElfBuilder, ctx: &Ctx) -> SymbolTables {
    let (locals, others): (Vec<_>, Vec<_>) = b.symbols.iter().partition(|s| s.bind == STB_LOCAL);
    let mut strtab = StrTab::new();
    let mut out = vec![0u8; usize_of(SYM64_SIZE)];
    for s in locals.iter().chain(&others) {
        let value = ctx.resolve(&s.at);
        p32(&mut out, strtab.add(&s.name));
        out.push((s.bind << 4) | (s.kind & 0x0f));
        out.push(0);
        p16(&mut out, ctx.shndx_of(&s.at, value));
        p64(&mut out, value);
        p64(&mut out, s.size);
    }
    SymbolTables {
        table: out,
        strings: strtab.into_bytes(),
        first_global: u32_of(u64_of(locals.len()) + 1),
    }
}

/// Writes one note: a 12-byte header, the name padded to 4 and the descriptor padded to `align`.
fn note_bytes(note: &Note) -> Vec<u8> {
    let mut out = Vec::new();
    p32(&mut out, u32_of(u64_of(note.name.len()) + 1));
    p32(&mut out, u32_of(u64_of(note.desc.len())));
    p32(&mut out, note.kind);
    out.extend_from_slice(note.name.as_bytes());
    out.push(0);
    out.resize(usize_of(align_up(u64_of(out.len()), 4)), 0);
    out.extend_from_slice(&note.desc);
    out.resize(usize_of(align_up(u64_of(out.len()), note.align.max(4))), 0);
    out
}

/// Returns one note section for each section name, in order of first use.
pub(crate) fn note_sections(b: &ElfBuilder) -> Vec<Sect> {
    let mut order: Vec<&str> = Vec::new();
    let mut groups: BTreeMap<&str, (Vec<u8>, u64)> = BTreeMap::new();
    for note in &b.notes {
        let name = note.section.as_str();
        if !order.contains(&name) {
            order.push(name);
        }
        let group = groups.entry(name).or_default();
        group.0.extend_from_slice(&note_bytes(note));
        group.1 = group.1.max(note.align.max(4));
    }
    order
        .into_iter()
        .filter_map(|name| {
            let (data, align) = groups.remove(name)?;
            Some(Sect::new(name, SHT_NOTE, SHF_ALLOC, align, 0, data))
        })
        .collect()
}
