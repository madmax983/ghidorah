//! The layout and the write of a full file.

use super::consts::{
    SHDR64_SIZE, SHF_ALLOC, SHF_EXECINSTR, SHF_INFO_LINK, SHF_WRITE, SHT_DYNAMIC, SHT_DYNSYM,
    SHT_FINI_ARRAY, SHT_GNU_HASH, SHT_HASH, SHT_INIT_ARRAY, SHT_NOBITS, SHT_PREINIT_ARRAY,
    SHT_PROGBITS, SHT_REL, SHT_RELA, SHT_RELR, SHT_STRTAB, SHT_SYMTAB, SYM64_SIZE,
};
use super::dynamic::{self, DynTables};
use super::emit::{phdr_plan, phdr_values, put_header, put_phdrs, put_section_headers};
use super::plan::{Ctx, Features, ImportPlan, Info, Sect, place};
use super::write::{StrTab, p64, put, u16_of, u32_of, u64_of, usize_of};
use super::{
    ElfBuilder, FixupKind, Layout, Loc, PlacedSection, Section, malformed, plt, symtab, unwind,
};

fn cstring(text: &str) -> Vec<u8> {
    let mut out = text.as_bytes().to_vec();
    out.push(0);
    out
}

/// Makes a section from a user section and applies its fixups.
fn user_sect(section: &Section, ctx: &Ctx) -> Sect {
    let nobits = section.kind == SHT_NOBITS;
    let data = if nobits {
        Vec::new()
    } else {
        section.data.clone()
    };
    let mut sect = Sect::new(
        &section.name,
        section.kind,
        section.flags,
        section.align,
        section.entsize,
        data,
    );
    if nobits {
        sect.mem_size = section.nobits_size;
    }
    let base = ctx.addr_of(&section.name);
    for fixup in &section.fixups {
        let target = ctx.resolve(&fixup.target);
        let place = base.wrapping_add(fixup.offset);
        match fixup.kind {
            FixupKind::Rel32 => {
                let value = super::write::rel32(target, place.wrapping_add(4));
                put(&mut sect.data, fixup.offset, &value.to_le_bytes());
            }
            FixupKind::Abs64 => put(&mut sect.data, fixup.offset, &target.to_le_bytes()),
            FixupKind::Abs32 => put(&mut sect.data, fixup.offset, &u32_of(target).to_le_bytes()),
        }
    }
    sect
}

/// Makes the sections of an array of absolute addresses.
fn array_sect(name: &str, kind: u32, places: &[Loc], ctx: &Ctx) -> Option<Sect> {
    if places.is_empty() {
        return None;
    }
    let mut data = Vec::new();
    for place in places {
        p64(&mut data, ctx.resolve(place));
    }
    Some(Sect::new(name, kind, SHF_WRITE | SHF_ALLOC, 8, 8, data))
}

/// The read-only sections that come first: interpreter, notes, hash tables and symbols.
fn head_group(
    b: &ElfBuilder,
    f: &Features,
    tables: Option<&DynTables>,
    ctx: &Ctx,
    relr_len: usize,
) -> Vec<Sect> {
    let mut out = Vec::new();
    if let Some(path) = &b.interp {
        out.push(Sect::new(
            ".interp",
            SHT_PROGBITS,
            SHF_ALLOC,
            1,
            0,
            cstring(path),
        ));
    }
    out.extend(symtab::note_sections(b));
    let Some(t) = tables else {
        return out;
    };
    if dynamic::has_gnu(b) {
        let data = dynamic::gnu_hash_bytes(t);
        out.push(Sect::new(".gnu.hash", SHT_GNU_HASH, SHF_ALLOC, 8, 0, data).linked(".dynsym"));
    }
    if dynamic::has_sysv(b) {
        let data = dynamic::sysv_hash_bytes(t);
        out.push(Sect::new(".hash", SHT_HASH, SHF_ALLOC, 8, 4, data).linked(".dynsym"));
    }
    let dynsym = dynamic::dynsym_bytes(t, ctx);
    out.push(
        Sect::new(".dynsym", SHT_DYNSYM, SHF_ALLOC, 8, SYM64_SIZE, dynsym)
            .linked(".dynstr")
            .with_info(Info::Num(1)),
    );
    out.push(Sect::new(
        ".dynstr",
        SHT_STRTAB,
        SHF_ALLOC,
        1,
        0,
        t.dynstr.clone(),
    ));
    if f.rela_dyn {
        let data = dynamic::rela_dyn_bytes(b, t, ctx);
        out.push(Sect::new(".rela.dyn", SHT_RELA, SHF_ALLOC, 8, 24, data).linked(".dynsym"));
    }
    if f.rel_dyn {
        let data = dynamic::rel_dyn_bytes(b, t, ctx);
        out.push(Sect::new(".rel.dyn", SHT_REL, SHF_ALLOC, 8, 16, data).linked(".dynsym"));
    }
    if f.relr {
        let data = dynamic::relr_bytes(b, ctx, relr_len);
        out.push(Sect::new(".relr.dyn", SHT_RELR, SHF_ALLOC, 8, 8, data));
    }
    if f.rela_plt {
        let data = dynamic::rela_plt_bytes(b, t, ctx);
        out.push(
            Sect::new(
                ".rela.plt",
                SHT_RELA,
                SHF_ALLOC | SHF_INFO_LINK,
                8,
                24,
                data,
            )
            .linked(".dynsym")
            .with_info(Info::Section(".got.plt")),
        );
    }
    out
}

/// The executable sections: PLT stubs, then the user code.
fn code_group(b: &ElfBuilder, f: &Features, plan: &ImportPlan, ctx: &Ctx) -> Vec<Sect> {
    let code = SHF_ALLOC | SHF_EXECINSTR;
    let mut out = Vec::new();
    if f.plt {
        let data = plt::plt_bytes(b, plan, ctx);
        out.push(Sect::new(".plt", SHT_PROGBITS, code, 16, plt::ENTRY, data));
    }
    if f.plt_got {
        let stride = plt::plt_got_stride(b.plt_style);
        let data = plt::plt_got_bytes(b, plan, ctx);
        out.push(Sect::new(
            ".plt.got",
            SHT_PROGBITS,
            code,
            stride,
            stride,
            data,
        ));
    }
    if f.plt_sec {
        let data = plt::plt_sec_bytes(plan, ctx);
        out.push(Sect::new(
            ".plt.sec",
            SHT_PROGBITS,
            code,
            16,
            plt::ENTRY,
            data,
        ));
    }
    let exec = |s: &&Section| {
        s.flags & SHF_ALLOC != 0 && s.flags & SHF_WRITE == 0 && s.flags & SHF_EXECINSTR != 0
    };
    out.extend(b.sections.iter().filter(exec).map(|s| user_sect(s, ctx)));
    out
}

/// The read-only data sections: user data, then the unwind tables.
fn data_group(b: &ElfBuilder, ctx: &Ctx) -> Vec<Sect> {
    let plain =
        |s: &&Section| s.flags & SHF_ALLOC != 0 && s.flags & (SHF_WRITE | SHF_EXECINSTR) == 0;
    let mut out: Vec<Sect> = b
        .sections
        .iter()
        .filter(plain)
        .map(|s| user_sect(s, ctx))
        .collect();
    if !b.fdes.is_empty() {
        let hdr = unwind::eh_frame_hdr(&b.fdes, ctx);
        out.push(Sect::new(
            ".eh_frame_hdr",
            SHT_PROGBITS,
            SHF_ALLOC,
            4,
            0,
            hdr,
        ));
        let (frame, _) = unwind::eh_frame(&b.fdes, ctx);
        out.push(Sect::new(".eh_frame", SHT_PROGBITS, SHF_ALLOC, 8, 0, frame));
    }
    out
}

/// The writable sections: arrays, `.dynamic`, GOT and user data. Zero-fill sections come last.
fn writable_group(
    b: &ElfBuilder,
    f: &Features,
    plan: &ImportPlan,
    tables: Option<&DynTables>,
    ctx: &Ctx,
) -> Vec<Sect> {
    let mut out = Vec::new();
    out.extend(array_sect(
        ".preinit_array",
        SHT_PREINIT_ARRAY,
        &b.preinit_array,
        ctx,
    ));
    out.extend(array_sect(
        ".init_array",
        SHT_INIT_ARRAY,
        &b.init_array,
        ctx,
    ));
    out.extend(array_sect(
        ".fini_array",
        SHT_FINI_ARRAY,
        &b.fini_array,
        ctx,
    ));
    if let Some(t) = tables {
        let data = dynamic::dynamic_bytes(b, t, f, ctx);
        out.push(
            Sect::new(".dynamic", SHT_DYNAMIC, SHF_WRITE | SHF_ALLOC, 8, 16, data)
                .linked(".dynstr"),
        );
    }
    if f.got {
        let data = plt::got_bytes(plan);
        out.push(Sect::new(
            ".got",
            SHT_PROGBITS,
            SHF_WRITE | SHF_ALLOC,
            8,
            8,
            data,
        ));
    }
    if f.got_plt {
        let data = plt::got_plt_bytes(b, plan, ctx);
        out.push(Sect::new(
            ".got.plt",
            SHT_PROGBITS,
            SHF_WRITE | SHF_ALLOC,
            8,
            8,
            data,
        ));
    }
    let writable = |s: &&Section| s.flags & SHF_ALLOC != 0 && s.flags & SHF_WRITE != 0;
    let (zero, filled): (Vec<&Section>, Vec<&Section>) = b
        .sections
        .iter()
        .filter(writable)
        .partition(|s| s.kind == SHT_NOBITS);
    out.extend(filled.into_iter().chain(zero).map(|s| user_sect(s, ctx)));
    out
}

/// The sections that no segment maps: user sections, `.symtab` and `.strtab`.
fn tail_group(b: &ElfBuilder, ctx: &Ctx) -> Vec<Sect> {
    let mut out: Vec<Sect> = b
        .sections
        .iter()
        .filter(|s| s.flags & SHF_ALLOC == 0)
        .map(|s| user_sect(s, ctx))
        .collect();
    if !b.symbols.is_empty() {
        let table = symtab::symtab(b, ctx);
        out.push(
            Sect::new(".symtab", SHT_SYMTAB, 0, 8, SYM64_SIZE, table.table)
                .linked(".strtab")
                .with_info(Info::Num(table.first_global)),
        );
        out.push(Sect::new(".strtab", SHT_STRTAB, 0, 1, 0, table.strings));
    }
    out
}

/// Makes all sections in header order, without the null section.
fn assemble(b: &ElfBuilder, relr_len: usize, ctx: &Ctx) -> Vec<Sect> {
    let f = Features::of(b);
    let plan = ImportPlan::of(b);
    let tables = f.dynamic.then(|| dynamic::tables(b));
    let mut sects = head_group(b, &f, tables.as_ref(), ctx, relr_len);
    sects.extend(code_group(b, &f, &plan, ctx));
    sects.extend(data_group(b, ctx));
    sects.extend(writable_group(b, &f, &plan, tables.as_ref(), ctx));
    if b.section_headers {
        sects.extend(tail_group(b, ctx));
        let mut names = StrTab::new();
        for s in &mut sects {
            s.name_off = names.add(&s.name);
        }
        let name_off = names.add(".shstrtab");
        let mut shstr = Sect::new(".shstrtab", SHT_STRTAB, 0, 1, 0, names.into_bytes());
        shstr.name_off = name_off;
        sects.push(shstr);
    }
    sects
}

/// Places the sections and builds the context. Section sizes do not depend on the context.
fn settle(b: &ElfBuilder, relr_len: usize) -> (Vec<Sect>, Ctx) {
    let mut ctx = Ctx::default();
    let mut sects = Vec::new();
    for _ in 0..3 {
        sects = assemble(b, relr_len, &ctx);
        let phnum = phdr_plan(b, &sects).len();
        place(&mut sects, b.base, phnum);
        let next = Ctx::of(b, &sects);
        let stable = next.addr == ctx.addr;
        ctx = next;
        if stable {
            break;
        }
    }
    (sects, ctx)
}

/// Finds the size of `.relr.dyn` in words. The size depends on the distance between places.
fn relr_length(b: &ElfBuilder) -> usize {
    let upper = b.relr.len();
    let mut len = upper;
    for _ in 0..4 {
        let (_, ctx) = settle(b, len);
        let want = dynamic::relr_words(b, &ctx).len();
        if want == len {
            return len;
        }
        len = want;
    }
    upper
}

fn entry_address(b: &ElfBuilder, ctx: &Ctx) -> u64 {
    if let Some(at) = &b.entry {
        return ctx.resolve(at);
    }
    b.sections
        .iter()
        .find(|s| s.flags & SHF_ALLOC != 0 && s.flags & SHF_EXECINSTR != 0)
        .map_or(0, |s| ctx.addr_of(&s.name))
}

fn layout_of(sects: &[Sect], ctx: &Ctx, entry: u64, phnum: usize) -> Layout {
    Layout {
        sections: sects
            .iter()
            .enumerate()
            .map(|(i, s)| PlacedSection {
                name: s.name.clone(),
                index: u16_of(u64_of(i) + 1),
                addr: s.addr,
                offset: s.offset,
                size: s.mem_size,
            })
            .collect(),
        symbols: ctx.symbols.clone(),
        plt: ctx.plt.clone(),
        plt_got: ctx.plt_got.clone(),
        got: ctx.got.clone(),
        entry,
        phnum: u16_of(u64_of(phnum)),
    }
}

/// Lays out and writes the file of `builder`.
pub(crate) fn build(builder: &ElfBuilder) -> (Vec<u8>, Layout) {
    let b = builder;
    let relr_len = relr_length(b);
    let (mut sects, ctx) = settle(b, relr_len);
    let plan = phdr_plan(b, &sects);
    let placement = place(&mut sects, b.base, plan.len());
    let phdrs = phdr_values(b, &plan, &sects, &placement);
    let entry = entry_address(b, &ctx);
    let total = if b.section_headers {
        placement.shoff + SHDR64_SIZE * (u64_of(sects.len()) + 1)
    } else {
        placement.file_end
    };
    let mut bytes = vec![0u8; usize_of(total)];
    put_header(
        &mut bytes,
        b,
        sects.len(),
        plan.len(),
        placement.shoff,
        entry,
    );
    put_phdrs(&mut bytes, &phdrs);
    for s in sects.iter().filter(|s| !s.is_nobits()) {
        put(&mut bytes, s.offset, &s.data);
    }
    if b.section_headers {
        put_section_headers(&mut bytes, &sects, &ctx, placement.shoff);
    }
    malformed::apply(&mut bytes, &b.malformed);
    let layout = layout_of(&sects, &ctx, entry, plan.len());
    (bytes, layout)
}
