//! The layout and the write of a full file.

use super::consts::{
    EHDR64_SIZE, ELFCLASS64, ELFDATA2LSB, PF_R, PF_W, PF_X, PHDR64_SIZE, PT_DYNAMIC,
    PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_NOTE, SHDR64_SIZE,
    SHF_ALLOC, SHF_EXECINSTR, SHF_INFO_LINK, SHF_WRITE, SHT_DYNAMIC, SHT_DYNSYM, SHT_FINI_ARRAY,
    SHT_GNU_HASH, SHT_HASH, SHT_INIT_ARRAY, SHT_NOBITS, SHT_NOTE, SHT_PREINIT_ARRAY, SHT_PROGBITS,
    SHT_REL, SHT_RELA, SHT_RELR, SHT_STRTAB, SHT_SYMTAB, SYM64_SIZE,
};
use super::dynamic::{self, DynTables};
use super::plan::{Ctx, Features, ImportPlan, Info, PAGE, Placement, Sect, load_count, place};
use super::write::{StrTab, p16, p32, p64, put, u16_of, u32_of, u64_of, usize_of};
use super::{
    ElfBuilder, FixupKind, Layout, Loc, PlacedSection, Section, malformed, plt, symtab, unwind,
};

/// The arrays that `PT_GNU_RELRO` covers, with `.dynamic` and `.got`.
const RELRO_SECTIONS: [&str; 5] = [
    ".preinit_array",
    ".init_array",
    ".fini_array",
    ".dynamic",
    ".got",
];

/// The kind of a program header, before the placement.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ph {
    Interp,
    Load(usize),
    Dynamic,
    Note(String),
    EhFrame,
    Stack(bool),
    Relro,
}

/// A program header with its values.
#[derive(Debug, Clone, Copy)]
struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

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

fn find<'a>(sects: &'a [Sect], name: &str) -> Option<&'a Sect> {
    sects.iter().find(|s| s.name == name)
}

/// Returns the offset range of the `PT_GNU_RELRO` segment.
fn relro_range(sects: &[Sect]) -> Option<(u64, u64)> {
    let mut range: Option<(u64, u64)> = None;
    for s in RELRO_SECTIONS.iter().filter_map(|n| find(sects, n)) {
        let (start, end) = (s.offset, s.offset.saturating_add(s.mem_size));
        range = Some(range.map_or((start, end), |(a, z)| (a.min(start), z.max(end))));
    }
    range
}

/// Lists the program headers in file order. The list does not depend on addresses.
fn phdr_plan(b: &ElfBuilder, sects: &[Sect]) -> Vec<Ph> {
    let mut out = Vec::new();
    if find(sects, ".interp").is_some() {
        out.push(Ph::Interp);
    }
    out.extend((0..load_count(sects)).map(Ph::Load));
    if find(sects, ".dynamic").is_some() {
        out.push(Ph::Dynamic);
    }
    out.extend(
        sects
            .iter()
            .filter(|s| s.kind == SHT_NOTE && s.is_alloc())
            .map(|s| Ph::Note(s.name.clone())),
    );
    if find(sects, ".eh_frame_hdr").is_some() {
        out.push(Ph::EhFrame);
    }
    if let Some(exec) = b.gnu_stack {
        out.push(Ph::Stack(exec));
    }
    if b.relro && relro_range(sects).is_some() {
        out.push(Ph::Relro);
    }
    out
}

fn section_phdr(sects: &[Sect], name: &str, kind: u32, flags: u32, align: u64, base: u64) -> Phdr {
    let (offset, size) = find(sects, name).map_or((0, 0), |s| (s.offset, s.mem_size));
    Phdr {
        kind,
        flags,
        offset,
        vaddr: base.wrapping_add(offset),
        filesz: size,
        memsz: size,
        align,
    }
}

/// Fills the program headers with the placed values.
fn phdr_values(b: &ElfBuilder, plan: &[Ph], sects: &[Sect], placement: &Placement) -> Vec<Phdr> {
    let base = b.base;
    plan.iter()
        .map(|ph| match ph {
            Ph::Interp => section_phdr(sects, ".interp", PT_INTERP, PF_R, 1, base),
            Ph::Load(i) => {
                let seg = placement
                    .segments
                    .get(*i)
                    .copied()
                    .unwrap_or(super::plan::Segment {
                        flags: PF_R,
                        offset: 0,
                        filesz: 0,
                        memsz: 0,
                    });
                Phdr {
                    kind: PT_LOAD,
                    flags: seg.flags,
                    offset: seg.offset,
                    vaddr: base.wrapping_add(seg.offset),
                    filesz: seg.filesz,
                    memsz: seg.memsz,
                    align: PAGE,
                }
            }
            Ph::Dynamic => section_phdr(sects, ".dynamic", PT_DYNAMIC, PF_R | PF_W, 8, base),
            Ph::Note(name) => {
                let align = find(sects, name).map_or(4, |s| s.align);
                section_phdr(sects, name, PT_NOTE, PF_R, align, base)
            }
            Ph::EhFrame => section_phdr(sects, ".eh_frame_hdr", PT_GNU_EH_FRAME, PF_R, 4, base),
            Ph::Stack(exec) => Phdr {
                kind: PT_GNU_STACK,
                flags: PF_R | PF_W | if *exec { PF_X } else { 0 },
                offset: 0,
                vaddr: 0,
                filesz: 0,
                memsz: 0,
                align: 16,
            },
            Ph::Relro => {
                let (start, end) = relro_range(sects).unwrap_or((0, 0));
                Phdr {
                    kind: PT_GNU_RELRO,
                    flags: PF_R,
                    offset: start,
                    vaddr: base.wrapping_add(start),
                    filesz: end - start,
                    memsz: end - start,
                    align: 1,
                }
            }
        })
        .collect()
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

fn put_header(
    out: &mut [u8],
    b: &ElfBuilder,
    sections: usize,
    phnum: usize,
    shoff: u64,
    entry: u64,
) {
    let mut h = b"\x7fELF".to_vec();
    h.extend_from_slice(&[ELFCLASS64, ELFDATA2LSB, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    p16(&mut h, b.e_type);
    p16(&mut h, b.machine);
    p32(&mut h, 1);
    p64(&mut h, entry);
    p64(&mut h, EHDR64_SIZE);
    p64(&mut h, if b.section_headers { shoff } else { 0 });
    p32(&mut h, 0);
    p16(&mut h, u16_of(EHDR64_SIZE));
    p16(&mut h, u16_of(PHDR64_SIZE));
    p16(&mut h, u16_of(u64_of(phnum)));
    p16(&mut h, u16_of(SHDR64_SIZE));
    let (shnum, shstrndx) = if b.section_headers {
        (sections + 1, sections)
    } else {
        (0, 0)
    };
    p16(&mut h, u16_of(u64_of(shnum)));
    p16(&mut h, u16_of(u64_of(shstrndx)));
    put(out, 0, &h);
}

fn put_phdrs(out: &mut [u8], phdrs: &[Phdr]) {
    for (i, ph) in phdrs.iter().enumerate() {
        let mut h = Vec::new();
        p32(&mut h, ph.kind);
        p32(&mut h, ph.flags);
        p64(&mut h, ph.offset);
        p64(&mut h, ph.vaddr);
        p64(&mut h, ph.vaddr);
        p64(&mut h, ph.filesz);
        p64(&mut h, ph.memsz);
        p64(&mut h, ph.align);
        put(out, EHDR64_SIZE + PHDR64_SIZE * u64_of(i), &h);
    }
}

fn index_of(ctx: &Ctx, name: &str) -> u32 {
    ctx.index.get(name).map_or(0, |i| u32::from(*i))
}

fn put_section_headers(out: &mut [u8], sects: &[Sect], ctx: &Ctx, shoff: u64) {
    for (i, s) in sects.iter().enumerate() {
        let mut h = Vec::new();
        p32(&mut h, s.name_off);
        p32(&mut h, s.kind);
        p64(&mut h, s.flags);
        p64(&mut h, s.addr);
        p64(&mut h, s.offset);
        p64(&mut h, s.mem_size);
        p32(
            &mut h,
            if s.link.is_empty() {
                0
            } else {
                index_of(ctx, s.link)
            },
        );
        p32(
            &mut h,
            match &s.info {
                Info::Num(n) => *n,
                Info::Section(name) => index_of(ctx, name),
            },
        );
        p64(&mut h, s.align);
        p64(&mut h, s.entsize);
        put(out, shoff + SHDR64_SIZE * u64_of(i + 1), &h);
    }
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
