//! Program headers, the file header and the section header table.

use super::ElfBuilder;
use super::consts::{
    EHDR64_SIZE, ELFCLASS64, ELFDATA2LSB, PF_R, PF_W, PF_X, PHDR64_SIZE, PT_DYNAMIC,
    PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_NOTE, SHDR64_SIZE,
    SHT_NOTE,
};
use super::plan::{Ctx, Info, PAGE, Placement, Sect, Segment, load_count};
use super::write::{p16, p32, p64, put, u16_of, u64_of};

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
pub(super) enum Ph {
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
pub(super) struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
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
pub(super) fn phdr_plan(b: &ElfBuilder, sects: &[Sect]) -> Vec<Ph> {
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
pub(super) fn phdr_values(
    b: &ElfBuilder,
    plan: &[Ph],
    sects: &[Sect],
    placement: &Placement,
) -> Vec<Phdr> {
    let base = b.base;
    plan.iter()
        .map(|ph| match ph {
            Ph::Interp => section_phdr(sects, ".interp", PT_INTERP, PF_R, 1, base),
            Ph::Load(i) => {
                let seg = placement.segments.get(*i).copied().unwrap_or(Segment {
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

pub(super) fn put_header(
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

pub(super) fn put_phdrs(out: &mut [u8], phdrs: &[Phdr]) {
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

pub(super) fn put_section_headers(out: &mut [u8], sects: &[Sect], ctx: &Ctx, shoff: u64) {
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
