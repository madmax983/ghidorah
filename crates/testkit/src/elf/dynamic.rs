//! Dynamic linking tables: `.dynsym`, `.dynstr`, hash tables, relocations and `.dynamic`.

use std::collections::BTreeMap;

use super::consts::{
    DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS, DT_FLAGS_1, DT_GNU_HASH, DT_HASH, DT_INIT_ARRAY,
    DT_INIT_ARRAYSZ, DT_JMPREL, DT_NEEDED, DT_NULL, DT_PLTGOT, DT_PLTREL, DT_PLTRELSZ,
    DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_REL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELENT,
    DT_RELR, DT_RELRENT, DT_RELRSZ, DT_RELSZ, DT_RPATH, DT_RUNPATH, DT_SONAME, DT_STRSZ, DT_STRTAB,
    DT_SYMENT, DT_SYMTAB, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, STB_GLOBAL, STT_FUNC, SYM64_SIZE,
};
use super::plan::{Ctx, Features, ImportPlan};
use super::write::{StrTab, p16, p32, p64, u32_of, u64_of, usize_of};
use super::{ElfBuilder, HashStyle, Loc, RelocTable};

/// The shift of the GNU hash Bloom filter.
const BLOOM_SHIFT: u32 = 6;

/// One entry of `.dynsym` after the null entry.
#[derive(Debug, Clone)]
pub(crate) struct DynSym {
    pub(crate) name: String,
    pub(crate) name_off: u32,
    pub(crate) info: u8,
    /// The place of a defined symbol, or `None` for an import.
    pub(crate) at: Option<Loc>,
    pub(crate) size: u64,
}

/// The dynamic symbol table and the strings of `.dynamic`.
#[derive(Debug, Clone)]
pub(crate) struct DynTables {
    pub(crate) dynstr: Vec<u8>,
    pub(crate) syms: Vec<DynSym>,
    pub(crate) index: BTreeMap<String, u32>,
    /// The `.dynsym` index of the first hashed symbol.
    pub(crate) symoffset: u32,
    pub(crate) nbuckets: u32,
    needed: Vec<u32>,
    soname: Option<u32>,
    rpath: Option<u32>,
    runpath: Option<u32>,
}

/// Returns the GNU hash of `name`.
pub(crate) fn gnu_hash(name: &str) -> u32 {
    name.bytes().fold(5381u32, |h, c| {
        h.wrapping_mul(33).wrapping_add(u32::from(c))
    })
}

/// Returns the System V ELF hash of `name`.
pub(crate) fn sysv_hash(name: &str) -> u32 {
    let mut h = 0u32;
    for c in name.bytes() {
        h = (h << 4).wrapping_add(u32::from(c));
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Returns `true` when the file has a `.gnu.hash` section.
pub(crate) const fn has_gnu(b: &ElfBuilder) -> bool {
    matches!(b.hash, HashStyle::Gnu | HashStyle::Both)
}

/// Returns `true` when the file has a `.hash` section.
pub(crate) const fn has_sysv(b: &ElfBuilder) -> bool {
    matches!(b.hash, HashStyle::Sysv | HashStyle::Both)
}

/// Builds the dynamic symbol table: imports first, then exports.
///
/// With a GNU hash table the exports are sorted by bucket, as that table needs.
pub(crate) fn tables(b: &ElfBuilder) -> DynTables {
    let mut strtab = StrTab::new();
    let needed = b.needed.iter().map(|n| strtab.add(n)).collect();
    let soname = b.soname.as_deref().map(|s| strtab.add(s));
    let rpath = b.rpath.as_deref().map(|s| strtab.add(s));
    let runpath = b.runpath.as_deref().map(|s| strtab.add(s));
    let mut syms: Vec<DynSym> = b
        .imports
        .iter()
        .map(|(name, _)| DynSym {
            name: name.clone(),
            name_off: strtab.add(name),
            info: (STB_GLOBAL << 4) | STT_FUNC,
            at: None,
            size: 0,
        })
        .collect();
    let symoffset = u32_of(u64_of(syms.len()) + 1);
    let nbuckets = u32_of(u64_of(b.exports.len().div_ceil(2)).max(1));
    let mut exports: Vec<&super::Symbol> = b.exports.iter().collect();
    if has_gnu(b) {
        exports.sort_by_key(|s| gnu_hash(&s.name) % nbuckets);
    }
    for symbol in exports {
        syms.push(DynSym {
            name: symbol.name.clone(),
            name_off: strtab.add(&symbol.name),
            info: (symbol.bind << 4) | (symbol.kind & 0x0f),
            at: Some(symbol.at.clone()),
            size: symbol.size,
        });
    }
    let mut index = BTreeMap::new();
    for (i, sym) in syms.iter().enumerate() {
        index
            .entry(sym.name.clone())
            .or_insert_with(|| u32_of(u64_of(i) + 1));
    }
    DynTables {
        dynstr: strtab.into_bytes(),
        syms,
        index,
        symoffset,
        nbuckets,
        needed,
        soname,
        rpath,
        runpath,
    }
}

/// Writes `.dynsym`.
pub(crate) fn dynsym_bytes(t: &DynTables, ctx: &Ctx) -> Vec<u8> {
    let mut out = vec![0u8; usize_of(SYM64_SIZE)];
    for sym in &t.syms {
        let (value, shndx) = sym.at.as_ref().map_or((0, 0), |at| {
            let value = ctx.resolve(at);
            (value, ctx.shndx_of(at, value))
        });
        p32(&mut out, sym.name_off);
        out.push(sym.info);
        out.push(0);
        p16(&mut out, shndx);
        p64(&mut out, value);
        p64(&mut out, sym.size);
    }
    out
}

/// Writes `.gnu.hash`. The exported symbols are the hashed symbols.
pub(crate) fn gnu_hash_bytes(t: &DynTables) -> Vec<u8> {
    let first = usize_of(u64::from(t.symoffset)).saturating_sub(1);
    let exported = t.syms.get(first..).unwrap_or_default();
    let hashes: Vec<u32> = exported.iter().map(|s| gnu_hash(&s.name)).collect();
    let mut bloom = 0u64;
    for h in &hashes {
        bloom |= 1u64 << (h % 64);
        bloom |= 1u64 << ((h >> BLOOM_SHIFT) % 64);
    }
    let mut buckets = vec![0u32; usize_of(u64::from(t.nbuckets))];
    let mut chains = Vec::with_capacity(hashes.len());
    for (pos, h) in hashes.iter().enumerate() {
        let bucket = h % t.nbuckets;
        if let Some(slot) = buckets.get_mut(usize_of(u64::from(bucket)))
            && *slot == 0
        {
            *slot = t.symoffset + u32_of(u64_of(pos));
        }
        let last = hashes
            .get(pos + 1)
            .is_none_or(|next| next % t.nbuckets != bucket);
        chains.push((h & !1) | u32::from(last));
    }
    let mut out = Vec::new();
    p32(&mut out, t.nbuckets);
    p32(&mut out, t.symoffset);
    p32(&mut out, 1);
    p32(&mut out, BLOOM_SHIFT);
    p64(&mut out, bloom);
    for v in buckets.iter().chain(&chains) {
        p32(&mut out, *v);
    }
    out
}

/// Writes `.hash`. All dynamic symbols are hashed.
pub(crate) fn sysv_hash_bytes(t: &DynTables) -> Vec<u8> {
    let nchain = t.syms.len() + 1;
    let nbucket = (nchain / 2).max(1);
    let mut buckets = vec![0u32; nbucket];
    let mut chain = vec![0u32; nchain];
    for (i, sym) in t.syms.iter().enumerate() {
        let slot = usize_of(u64::from(sysv_hash(&sym.name))) % nbucket;
        let index = u32_of(u64_of(i) + 1);
        let previous = buckets.get(slot).copied().unwrap_or(0);
        if let Some(entry) = chain.get_mut(i + 1) {
            *entry = previous;
        }
        if let Some(head) = buckets.get_mut(slot) {
            *head = index;
        }
    }
    let mut out = Vec::new();
    p32(&mut out, u32_of(u64_of(nbucket)));
    p32(&mut out, u32_of(u64_of(nchain)));
    for v in buckets.iter().chain(&chain) {
        p32(&mut out, *v);
    }
    out
}

fn symbol_index(t: &DynTables, name: Option<&String>) -> u64 {
    name.and_then(|n| t.index.get(n))
        .map_or(0, |i| u64::from(*i))
}

/// Writes `.rela.dyn`: the user RELA entries, then one `GLOB_DAT` entry for each `.got` import.
pub(crate) fn rela_dyn_bytes(b: &ElfBuilder, t: &DynTables, ctx: &Ctx) -> Vec<u8> {
    let mut out = Vec::new();
    for r in b.relocs.iter().filter(|r| r.table == RelocTable::Rela) {
        p64(&mut out, ctx.resolve(&r.at));
        p64(
            &mut out,
            (symbol_index(t, r.sym.as_ref()) << 32) | u64::from(r.kind),
        );
        p64(&mut out, r.addend.cast_unsigned());
    }
    for name in &ImportPlan::of(b).got_slots {
        p64(&mut out, ctx.got.get(name).copied().unwrap_or(0));
        p64(
            &mut out,
            (symbol_index(t, Some(name)) << 32) | u64::from(R_X86_64_GLOB_DAT),
        );
        p64(&mut out, 0);
    }
    out
}

/// Writes `.rel.dyn`: the user REL entries.
pub(crate) fn rel_dyn_bytes(b: &ElfBuilder, t: &DynTables, ctx: &Ctx) -> Vec<u8> {
    let mut out = Vec::new();
    for r in b.relocs.iter().filter(|r| r.table == RelocTable::Rel) {
        p64(&mut out, ctx.resolve(&r.at));
        p64(
            &mut out,
            (symbol_index(t, r.sym.as_ref()) << 32) | u64::from(r.kind),
        );
    }
    out
}

/// Writes `.rela.plt`: one `JUMP_SLOT` entry for each PLT import.
pub(crate) fn rela_plt_bytes(b: &ElfBuilder, t: &DynTables, ctx: &Ctx) -> Vec<u8> {
    let mut out = Vec::new();
    for name in &ImportPlan::of(b).plt {
        p64(&mut out, ctx.got.get(name).copied().unwrap_or(0));
        p64(
            &mut out,
            (symbol_index(t, Some(name)) << 32) | u64::from(R_X86_64_JUMP_SLOT),
        );
        p64(&mut out, 0);
    }
    out
}

/// Encodes the places of `.relr.dyn`: an address word, then 63-bit bitmaps.
pub(crate) fn relr_words(b: &ElfBuilder, ctx: &Ctx) -> Vec<u64> {
    let mut places: Vec<u64> = b.relr.iter().map(|l| ctx.resolve(l) & !7).collect();
    places.sort_unstable();
    places.dedup();
    let mut out = Vec::new();
    let mut next = 0;
    while let Some(&first) = places.get(next) {
        out.push(first);
        next += 1;
        let mut base = first.wrapping_add(8);
        loop {
            let limit = base.saturating_add(63 * 8);
            let mut word = 1u64;
            let mut any = false;
            while let Some(&place) = places.get(next) {
                if place >= limit {
                    break;
                }
                let bit = (place.saturating_sub(base) / 8 + 1).min(63);
                word |= 1u64 << bit;
                any = true;
                next += 1;
            }
            if !any {
                break;
            }
            out.push(word);
            base = limit;
        }
    }
    out
}

/// Writes `.relr.dyn` with exactly `len` words. A short table gets empty bitmaps.
pub(crate) fn relr_bytes(b: &ElfBuilder, ctx: &Ctx, len: usize) -> Vec<u8> {
    let mut words = relr_words(b, ctx);
    words.resize(len, 1);
    let mut out = Vec::new();
    for w in words {
        p64(&mut out, w);
    }
    out
}

/// Adds the address tag and the size tag of an array section.
fn array_entries(
    out: &mut Vec<(u64, u64)>,
    ctx: &Ctx,
    name: &str,
    present: bool,
    tags: (u64, u64),
) {
    if present {
        out.push((tags.0, ctx.addr_of(name)));
        out.push((tags.1, ctx.size_of(name)));
    }
}

/// Writes `.dynamic`. The last entry is `DT_NULL`.
pub(crate) fn dynamic_bytes(b: &ElfBuilder, t: &DynTables, f: &Features, ctx: &Ctx) -> Vec<u8> {
    let mut e: Vec<(u64, u64)> = Vec::new();
    e.extend(t.needed.iter().map(|o| (DT_NEEDED, u64::from(*o))));
    for (tag, off) in [
        (DT_SONAME, t.soname),
        (DT_RPATH, t.rpath),
        (DT_RUNPATH, t.runpath),
    ] {
        if let Some(off) = off {
            e.push((tag, u64::from(off)));
        }
    }
    if has_sysv(b) {
        e.push((DT_HASH, ctx.addr_of(".hash")));
    }
    if has_gnu(b) {
        e.push((DT_GNU_HASH, ctx.addr_of(".gnu.hash")));
    }
    e.push((DT_STRTAB, ctx.addr_of(".dynstr")));
    e.push((DT_SYMTAB, ctx.addr_of(".dynsym")));
    e.push((DT_STRSZ, ctx.size_of(".dynstr")));
    e.push((DT_SYMENT, SYM64_SIZE));
    if f.got_plt {
        e.push((DT_PLTGOT, ctx.addr_of(".got.plt")));
    }
    if f.rela_plt {
        e.push((DT_PLTRELSZ, ctx.size_of(".rela.plt")));
        e.push((DT_PLTREL, DT_RELA));
        e.push((DT_JMPREL, ctx.addr_of(".rela.plt")));
    }
    if f.rela_dyn {
        e.push((DT_RELA, ctx.addr_of(".rela.dyn")));
        e.push((DT_RELASZ, ctx.size_of(".rela.dyn")));
        e.push((DT_RELAENT, 24));
    }
    if f.rel_dyn {
        e.push((DT_REL, ctx.addr_of(".rel.dyn")));
        e.push((DT_RELSZ, ctx.size_of(".rel.dyn")));
        e.push((DT_RELENT, 16));
    }
    if f.relr {
        e.push((DT_RELR, ctx.addr_of(".relr.dyn")));
        e.push((DT_RELRSZ, ctx.size_of(".relr.dyn")));
        e.push((DT_RELRENT, 8));
    }
    array_entries(
        &mut e,
        ctx,
        ".init_array",
        !b.init_array.is_empty(),
        (DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
    );
    array_entries(
        &mut e,
        ctx,
        ".fini_array",
        !b.fini_array.is_empty(),
        (DT_FINI_ARRAY, DT_FINI_ARRAYSZ),
    );
    array_entries(
        &mut e,
        ctx,
        ".preinit_array",
        !b.preinit_array.is_empty(),
        (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ),
    );
    if let Some(flags) = b.flags {
        e.push((DT_FLAGS, flags));
    }
    if let Some(flags) = b.flags_1 {
        e.push((DT_FLAGS_1, flags));
    }
    e.push((DT_NULL, 0));
    let mut out = Vec::new();
    for (tag, value) in e {
        p64(&mut out, tag);
        p64(&mut out, value);
    }
    out
}
