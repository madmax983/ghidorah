//! More tests of `ElfBuilder`: the builder contract beyond the RED table.

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod elf_read;

use elf_read::Elf;
use ghidorah_testkit::elf::consts::{
    DF_1_NOW, DF_BIND_NOW, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_FLAGS, DT_FLAGS_1, DT_PREINIT_ARRAY,
    DT_PREINIT_ARRAYSZ, DT_REL, DT_RELENT, DT_RELSZ, DT_RPATH, DT_RUNPATH, DT_SONAME, DT_STRTAB,
    EM_AARCH64, ET_DYN, PT_DYNAMIC, PT_LOAD, R_X86_64_64, R_X86_64_RELATIVE, SHF_ALLOC, SHF_WRITE,
    SHT_PROGBITS,
};
use ghidorah_testkit::elf::{
    self, EhdrField, ElfBuilder, FixupKind, HashStyle, ImportKind, Loc, Malformed, PhdrField,
    PltStyle, Reloc, RelocTable, Section, ShdrField, Symbol,
};
use ghidorah_testkit::pbt;

fn text() -> Section {
    Section::code(".text", &[0xc3; 32])
}

fn off(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[test]
fn elf_ibt_plt0_and_plt_got_stub() {
    let b = ElfBuilder::exec()
        .section(text())
        .import("puts", ImportKind::Plt)
        .import("free", ImportKind::PltGot)
        .plt_style(PltStyle::Ibt)
        .needed("libc.so.6");
    let (bytes, layout) = b.build_with_layout();
    let e = Elf::new(&bytes);
    let plt = e.section(".plt").unwrap_or_else(|| panic!("no .plt"));
    let got_plt = e
        .section(".got.plt")
        .unwrap_or_else(|| panic!("no .got.plt"));
    let at = off(plt.offset);
    assert_eq!(&bytes[at..at + 2], &[0xff, 0x35], "PLT0 push GOT[1]");
    assert_eq!(&bytes[at + 6..at + 9], &[0xf2, 0xff, 0x25], "PLT0 bnd jmp");
    let push = e.i32(plt.offset + 2);
    assert_eq!(
        (plt.addr + 6).wrapping_add_signed(i64::from(push)),
        got_plt.addr + 8
    );
    let jump = e.i32(plt.offset + 9);
    assert_eq!(
        (plt.addr + 13).wrapping_add_signed(i64::from(jump)),
        got_plt.addr + 16
    );
    let stub = layout.plt_got["free"];
    let s = off(e.va_to_off(stub).unwrap_or(0));
    assert_eq!(&bytes[s..s + 6], &[0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25]);
    let disp = e.i32(e.va_to_off(stub).unwrap_or(0) + 6);
    assert_eq!(
        (stub + 10).wrapping_add_signed(i64::from(disp)),
        layout.got["free"]
    );
    let got = e.section(".got").unwrap_or_else(|| panic!("no .got"));
    assert_eq!(layout.got["free"], got.addr, "the PltGot slot is in .got");
}

#[test]
fn elf_got_plt_header_and_lazy_slots() {
    let b = ElfBuilder::exec()
        .section(text())
        .import("puts", ImportKind::Plt)
        .import("exit", ImportKind::Plt);
    let (bytes, layout) = b.build_with_layout();
    let e = Elf::new(&bytes);
    let plt = e.section(".plt").unwrap_or_else(|| panic!("no .plt"));
    let got_plt = e
        .section(".got.plt")
        .unwrap_or_else(|| panic!("no .got.plt"));
    let dynamic = e.section(".dynamic").unwrap_or_else(|| panic!("no .dyn"));
    assert_eq!(
        got_plt.size,
        24 + 16,
        "three reserved slots and two imports"
    );
    assert_eq!(e.u64(got_plt.offset), dynamic.addr, "GOT[0] holds .dynamic");
    assert_eq!(e.u64(got_plt.offset + 8), 0);
    assert_eq!(e.u64(got_plt.offset + 16), 0);
    assert_eq!(plt.size, 16 * 3, "PLT0 and two entries");
    for (i, name) in ["puts", "exit"].iter().enumerate() {
        let entry = plt.addr + 16 * (u64::try_from(i).unwrap_or(0) + 1);
        assert_eq!(layout.plt[*name], entry);
        let slot_off = got_plt.offset + 24 + 8 * u64::try_from(i).unwrap_or(0);
        assert_eq!(e.u64(slot_off), entry + 6, "the lazy slot of {name}");
        let at = e.va_to_off(entry).unwrap_or(0);
        assert_eq!(bytes[off(at) + 6], 0x68, "push imm32");
        assert_eq!(u64::from(e.u32(at + 7)), u64::try_from(i).unwrap_or(0));
        assert_eq!(bytes[off(at) + 11], 0xe9, "jmp PLT0");
        let rel = e.i32(at + 12);
        assert_eq!(
            (entry + 16).wrapping_add_signed(i64::from(rel)),
            plt.addr,
            "the lazy entry of {name} jumps to PLT0"
        );
    }
    assert_eq!(&bytes[off(plt.offset)..off(plt.offset) + 2], &[0xff, 0x35]);
    assert_eq!(
        &bytes[off(plt.offset) + 6..off(plt.offset) + 8],
        &[0xff, 0x25]
    );
}

#[test]
fn elf_rel_dyn_uses_16_byte_entries() {
    let b = ElfBuilder::dyn_object()
        .section(text())
        .section(Section::data(".data", &[0u8; 16]))
        .import("puts", ImportKind::Plt)
        .reloc(Reloc {
            table: RelocTable::Rel,
            at: Loc::section(".data", 0),
            kind: R_X86_64_RELATIVE,
            sym: None,
            addend: 5,
        })
        .reloc(Reloc {
            table: RelocTable::Rel,
            at: Loc::section(".data", 8),
            kind: R_X86_64_64,
            sym: Some("puts".to_string()),
            addend: 0,
        });
    let (bytes, layout) = b.build_with_layout();
    let e = Elf::new(&bytes);
    let rel = e
        .section(".rel.dyn")
        .unwrap_or_else(|| panic!("no .rel.dyn"));
    assert_eq!(rel.size, 32);
    assert_eq!(rel.entsize, 16);
    assert!(e.section(".rela.dyn").is_none());
    let data = layout.section(".data").map_or(0, |s| s.addr);
    assert_eq!(e.u64(rel.offset), data);
    assert_eq!(e.u64(rel.offset + 8), u64::from(R_X86_64_RELATIVE));
    assert_eq!(e.u64(rel.offset + 16), data + 8);
    assert_eq!(
        e.u64(rel.offset + 24),
        (1 << 32) | u64::from(R_X86_64_64),
        "the symbol index of puts is 1"
    );
    assert_eq!(e.dyn_value(DT_REL), Some(rel.addr));
    assert_eq!(e.dyn_value(DT_RELSZ), Some(32));
    assert_eq!(e.dyn_value(DT_RELENT), Some(16));
}

#[test]
fn elf_symtab_orders_locals_first() {
    let b = ElfBuilder::exec()
        .section(text())
        .symbol(Symbol::func("glob", Loc::section(".text", 0), 4))
        .symbol(Symbol::func("loc", Loc::section(".text", 4), 4).local())
        .symbol(Symbol::func("wk", Loc::section(".text", 8), 4).weak())
        .symbol(Symbol::object("abs", Loc::Abs(0x1234), 0));
    let bytes = b.build();
    let e = Elf::new(&bytes);
    let syms = e.symbols(".symtab");
    let names: Vec<&str> = syms.iter().map(|s| s.0.as_str()).collect();
    assert_eq!(names, ["", "loc", "glob", "wk", "abs"]);
    let symtab = e.section(".symtab").unwrap_or_else(|| panic!("no .symtab"));
    assert_eq!(symtab.info, 2, "the first non-local symbol");
    assert_eq!(symtab.entsize, 24);
    assert_eq!(syms[1].2, 0x02, "local function");
    assert_eq!(syms[2].2, 0x12, "global function");
    assert_eq!(syms[3].2, 0x22, "weak function");
    assert_eq!(syms[4].2, 0x11, "global object");
    assert_eq!(syms[2].3, 1, "section index of .text");
    assert_eq!((syms[4].1, syms[4].3), (0x1234, 0xfff1), "absolute symbol");
    assert_eq!(syms[3].1, syms[2].1 + 8, "values are virtual addresses");
}

#[test]
fn elf_static_file_has_no_dynamic_parts() {
    let plain = ElfBuilder::exec().section(text()).build();
    let e = Elf::new(&plain);
    for name in [".dynamic", ".dynsym", ".dynstr", ".gnu.hash", ".got.plt"] {
        assert!(e.section(name).is_none(), "{name}");
    }
    assert!(e.phdrs().iter().all(|p| p.p_type != PT_DYNAMIC));
    let forced = ElfBuilder::exec().section(text()).force_dynamic().build();
    let e = Elf::new(&forced);
    assert!(e.section(".dynamic").is_some());
    assert!(e.phdrs().iter().any(|p| p.p_type == PT_DYNAMIC));
    assert_eq!(e.symbols(".dynsym").len(), 1, "only the null symbol");
}

#[test]
fn elf_user_non_alloc_sections_follow_the_alloc_sections() {
    let b = ElfBuilder::exec()
        .section(Section::new(".comment", SHT_PROGBITS, 0, b"hi\0"))
        .section(text())
        .symbol(Symbol::func("f", Loc::section(".text", 0), 1));
    let bytes = b.build();
    let e = Elf::new(&bytes);
    let names: Vec<String> = e.shdrs().into_iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        ["", ".text", ".comment", ".symtab", ".strtab", ".shstrtab"]
    );
    let comment = e
        .section(".comment")
        .unwrap_or_else(|| panic!("no .comment"));
    assert_eq!(comment.addr, 0);
    assert_eq!(comment.flags & SHF_ALLOC, 0);
    assert_eq!(
        &bytes[off(comment.offset)..off(comment.offset) + 3],
        b"hi\0"
    );
    let covered = e.phdrs().into_iter().any(|p| {
        p.p_type == PT_LOAD && comment.offset >= p.offset && comment.offset < p.offset + p.filesz
    });
    assert!(!covered, "no PT_LOAD maps a non-alloc section");
}

#[test]
fn elf_layout_reports_placed_sections_and_symbols() {
    let (bytes, layout) = elf::minimal().build_with_layout();
    let e = Elf::new(&bytes);
    let headers = e.shdrs();
    assert_eq!(layout.sections.len(), headers.len() - 1);
    for (placed, header) in layout.sections.iter().zip(headers.iter().skip(1)) {
        assert_eq!(placed.name, header.name);
        assert_eq!(placed.addr, header.addr);
        assert_eq!(placed.offset, header.offset);
        assert_eq!(placed.size, header.size);
    }
    let indexes: Vec<u16> = layout.sections.iter().map(|s| s.index).collect();
    assert_eq!(indexes, [1, 2, 3, 4]);
    assert_eq!(layout.symbols.len(), 1);
    assert_eq!(layout.phnum, 1);
    assert!(layout.plt.is_empty() && layout.plt_got.is_empty() && layout.got.is_empty());
    assert_eq!(
        layout.section(".symtab").map(|s| s.addr),
        Some(0),
        "a section that is not allocated has no address"
    );
}

/// Returns the System V ELF hash of `name`.
fn sysv_hash(name: &str) -> u32 {
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

/// Returns the GNU hash of `name`.
fn gnu_hash(name: &str) -> u32 {
    name.bytes().fold(5381u32, |h, c| {
        h.wrapping_mul(33).wrapping_add(u32::from(c))
    })
}

fn lookup_sysv(e: &Elf, name: &str) -> Option<u64> {
    let h = e.section(".hash")?;
    let nbucket = u64::from(e.u32(h.offset));
    let nchain = u64::from(e.u32(h.offset + 4));
    let mut index = u64::from(e.u32(h.offset + 8 + 4 * (u64::from(sysv_hash(name)) % nbucket)));
    let names = e.symbols(".dynsym");
    let mut steps = 0;
    while index != 0 && steps <= nchain {
        if names.get(off(index)).is_some_and(|s| s.0 == name) {
            return Some(index);
        }
        index = u64::from(e.u32(h.offset + 8 + 4 * nbucket + 4 * index));
        steps += 1;
    }
    None
}

fn lookup_gnu(e: &Elf, name: &str) -> Option<u64> {
    let h = e.section(".gnu.hash")?;
    let nbuckets = u64::from(e.u32(h.offset));
    let symoffset = u64::from(e.u32(h.offset + 4));
    let bloom = u64::from(e.u32(h.offset + 8));
    let hash = gnu_hash(name);
    let buckets = h.offset + 16 + 8 * bloom;
    let chains = buckets + 4 * nbuckets;
    let mut index = u64::from(e.u32(buckets + 4 * (u64::from(hash) % nbuckets)));
    let names = e.symbols(".dynsym");
    while index >= symoffset && index != 0 {
        let chain = e.u32(chains + 4 * (index - symoffset));
        if chain | 1 == hash | 1 && names.get(off(index)).is_some_and(|s| s.0 == name) {
            return Some(index);
        }
        if chain & 1 == 1 {
            break;
        }
        index += 1;
    }
    None
}

#[test]
fn elf_hash_tables_find_every_symbol() {
    let mut b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3; 128]))
        .hash(HashStyle::Both)
        .import("puts", ImportKind::Plt)
        .import("malloc", ImportKind::Plt);
    for i in 0..20u64 {
        b = b.export(Symbol::func(
            &format!("fn_{i}"),
            Loc::section(".text", i),
            1,
        ));
    }
    let bytes = b.build();
    let e = Elf::new(&bytes);
    let names: Vec<String> = e.symbols(".dynsym").into_iter().map(|s| s.0).collect();
    assert_eq!(names.len(), 23);
    for (i, name) in names.iter().enumerate().skip(1) {
        let want = u64::try_from(i).ok();
        assert_eq!(lookup_sysv(&e, name), want, "System V hash of {name}");
        if name.starts_with("fn_") {
            assert_eq!(lookup_gnu(&e, name), want, "GNU hash of {name}");
        }
    }
    assert_eq!(lookup_sysv(&e, "missing"), None);
    assert_eq!(lookup_gnu(&e, "missing"), None);
}

#[test]
fn elf_catalog_variants_apply_their_defect() {
    let variants = elf::malformed_variants();
    let find = |name: &str| {
        variants
            .iter()
            .find(|v| v.name == name)
            .unwrap_or_else(|| panic!("no variant {name}"))
    };
    assert_ne!(find("bad_magic").bytes[0], 0x7f);
    assert_eq!(find("truncated_ehdr").bytes.len(), 40);
    assert!(find("empty_file").bytes.is_empty());
    assert_eq!(Elf::new(&find("phentsize_small").bytes).e_phentsize(), 32);
    assert_eq!(Elf::new(&find("shentsize_small").bytes).e_shentsize(), 16);
    assert_eq!(
        Elf::new(&find("phoff_overflow").bytes).e_phoff(),
        u64::MAX - 15
    );
    let note = Elf::new(&find("note_align_16").bytes);
    assert!(
        note.phdrs().iter().any(|p| p.align == 16),
        "one program header has p_align 16"
    );
    let reloc = Elf::new(&find("unsupported_reloc").bytes);
    assert!(reloc.section(".rela.dyn").is_some());
    let dynsym = Elf::new(&find("dynsym_entsize_zero").bytes);
    assert_eq!(dynsym.section(".dynsym").map(|s| s.entsize), Some(0));
}

#[test]
fn elf_random_builders_keep_their_tables_inside_the_file() {
    pbt::check("elf_random_builders", 64, |g| {
        let mut b = if g.bool() {
            ElfBuilder::exec()
        } else {
            ElfBuilder::dyn_object()
        };
        b = b.section(Section::code(".text", &g.bytes(40)));
        if g.bool() {
            b = b.section(Section::rodata(".rodata", &g.bytes(40)));
        }
        if g.bool() {
            b = b.section(Section::data(".data", &[0u8; 64]));
        }
        if g.bool() {
            b = b.section(Section::bss(".bss", g.range(1, 5000)));
        }
        for i in 0..g.draw(4) {
            let kind = match g.draw(3) {
                0 => ImportKind::Plt,
                1 => ImportKind::Got,
                _ => ImportKind::PltGot,
            };
            b = b.import(&format!("imp{i}"), kind);
        }
        for i in 0..g.draw(4) {
            b = b.export(Symbol::func(
                &format!("exp{i}"),
                Loc::section(".text", i),
                1,
            ));
        }
        if g.bool() {
            b = b.plt_style(PltStyle::Ibt);
        }
        if g.bool() {
            b = b.build_id(&g.bytes(24)).gnu_stack(g.bool()).gnu_relro();
        }
        let bytes = b.build();
        if b.build() != bytes {
            return Err("two builds differ".to_string());
        }
        let e = Elf::new(&bytes);
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        for p in e.phdrs() {
            if p.p_type == PT_LOAD && p.offset + p.filesz > len {
                return Err(format!("segment {p:?} runs past the file"));
            }
        }
        for s in e.shdrs().iter().skip(1) {
            let nobits = s.sh_type == 8;
            if !nobits && s.offset + s.size > len {
                return Err(format!("section {} runs past the file", s.name));
            }
        }
        if e.e_type() != ET_DYN && e.e_type() != 2 {
            return Err("bad e_type".to_string());
        }
        Ok(())
    });
}

fn dynstr(e: &Elf, value: u64) -> String {
    let strtab = e
        .dyn_value(DT_STRTAB)
        .and_then(|va| e.va_to_off(va))
        .unwrap_or(0);
    e.cstr(strtab + value)
}

#[test]
fn elf_builder_setters_reach_the_file() {
    let code = Section::code(".fix", &[0u8; 16])
        .fixup(0, FixupKind::Abs32, Loc::Abs(0x1122_3344))
        .fixup(4, FixupKind::Abs64, Loc::PltGot("free".to_string()));
    let data = Section::new(
        ".mydata",
        SHT_PROGBITS,
        SHF_ALLOC | SHF_WRITE,
        &[1, 2, 3, 4],
    )
    .align(32)
    .entsize(4);
    let b = ElfBuilder::dyn_object()
        .machine(EM_AARCH64)
        .base(0x80_0000)
        .section(text())
        .section(code)
        .section(data)
        .import("free", ImportKind::PltGot)
        .rpath("/lib")
        .runpath("$ORIGIN")
        .soname("libx.so")
        .dt_flags(DF_BIND_NOW)
        .dt_flags_1(DF_1_NOW)
        .fini_array(Loc::section(".text", 4))
        .preinit_array(Loc::Abs(0xdead));
    let (bytes, layout) = b.build_with_layout();
    let e = Elf::new(&bytes);
    assert_eq!(e.e_machine(), EM_AARCH64);
    let text_at = layout.section(".text").map_or(0, |s| s.addr);
    assert_eq!(
        text_at,
        0x80_0000 + e.section(".text").map_or(0, |s| s.offset)
    );
    let mydata = e.section(".mydata").unwrap_or_else(|| panic!("no .mydata"));
    assert_eq!((mydata.align, mydata.entsize), (32, 4));
    assert_eq!(mydata.addr % 32, 0);
    let fix = e.section(".fix").unwrap_or_else(|| panic!("no .fix"));
    assert_eq!(e.u32(fix.offset), 0x1122_3344, "the Abs32 fixup");
    assert_eq!(
        e.u64(fix.offset + 4),
        layout.plt_got["free"],
        "the Abs64 fixup"
    );
    let name = |tag| e.dyn_value(tag).map(|v| dynstr(&e, v));
    assert_eq!(name(DT_RPATH).as_deref(), Some("/lib"));
    assert_eq!(name(DT_RUNPATH).as_deref(), Some("$ORIGIN"));
    assert_eq!(name(DT_SONAME).as_deref(), Some("libx.so"));
    assert_eq!(e.dyn_value(DT_FLAGS), Some(DF_BIND_NOW));
    assert_eq!(e.dyn_value(DT_FLAGS_1), Some(DF_1_NOW));
    let fini = e
        .section(".fini_array")
        .unwrap_or_else(|| panic!("no .fini_array"));
    assert_eq!(e.dyn_value(DT_FINI_ARRAY), Some(fini.addr));
    assert_eq!(e.dyn_value(DT_FINI_ARRAYSZ), Some(8));
    assert_eq!(e.u64(fini.offset), text_at + 4);
    let pre = e
        .section(".preinit_array")
        .unwrap_or_else(|| panic!("no .preinit_array"));
    assert_eq!(e.dyn_value(DT_PREINIT_ARRAY), Some(pre.addr));
    assert_eq!(e.dyn_value(DT_PREINIT_ARRAYSZ), Some(8));
    assert_eq!(e.u64(pre.offset), 0xdead);
    for p in e.phdrs().iter().filter(|p| p.p_type == PT_LOAD) {
        assert_eq!(p.vaddr - p.offset, 0x80_0000);
    }
}

fn with_knob(knob: Malformed) -> Vec<u8> {
    ElfBuilder::exec()
        .section(text())
        .symbol(Symbol::func("f", Loc::section(".text", 0), 1))
        .malformed(knob)
        .build()
}

#[test]
fn elf_malformed_fields_write_their_offsets() {
    let ehdr = |field, value| with_knob(Malformed::Ehdr(field, value));
    assert_eq!(Elf::new(&ehdr(EhdrField::Type, 3)).e_type(), 3);
    assert_eq!(Elf::new(&ehdr(EhdrField::Machine, 183)).e_machine(), 183);
    let entry = 0x1234_5678_9abc;
    assert_eq!(Elf::new(&ehdr(EhdrField::Entry, entry)).e_entry(), entry);
    assert_eq!(Elf::new(&ehdr(EhdrField::Phoff, 0x20)).e_phoff(), 0x20);
    assert_eq!(Elf::new(&ehdr(EhdrField::Shoff, 0x30)).e_shoff(), 0x30);
    assert_eq!(Elf::new(&ehdr(EhdrField::Phnum, 7)).e_phnum(), 7);
    assert_eq!(
        Elf::new(&ehdr(EhdrField::Shentsize, 0x44)).e_shentsize(),
        0x44
    );
    assert_eq!(Elf::new(&ehdr(EhdrField::Shnum, 9)).e_shnum(), 9);
    assert_eq!(Elf::new(&ehdr(EhdrField::Shstrndx, 2)).e_shstrndx(), 2);
    let phdr = |field, value| {
        let bytes = with_knob(Malformed::Phdr(0, field, value));
        Elf::new(&bytes).phdrs()[0]
    };
    assert_eq!(phdr(PhdrField::Type, 0x7000_0001).p_type, 0x7000_0001);
    assert_eq!(phdr(PhdrField::Flags, 7).flags, 7);
    assert_eq!(phdr(PhdrField::Offset, 0x10).offset, 0x10);
    assert_eq!(phdr(PhdrField::Vaddr, 0x7000).vaddr, 0x7000);
    assert_eq!(phdr(PhdrField::Filesz, 0x11).filesz, 0x11);
    assert_eq!(phdr(PhdrField::Memsz, 0x22).memsz, 0x22);
    assert_eq!(phdr(PhdrField::Align, 0x33).align, 0x33);
    let shdr = |field, value| {
        let bytes = with_knob(Malformed::Shdr(".text".to_string(), field, value));
        Elf::new(&bytes)
            .section(".text")
            .unwrap_or_else(|| panic!("no .text"))
    };
    assert_eq!(shdr(ShdrField::Type, 0x55).sh_type, 0x55);
    assert_eq!(shdr(ShdrField::Flags, 0x66).flags, 0x66);
    assert_eq!(shdr(ShdrField::Addr, 0x77).addr, 0x77);
    assert_eq!(shdr(ShdrField::Offset, 0x88).offset, 0x88);
    assert_eq!(shdr(ShdrField::Size, 0x99).size, 0x99);
    assert_eq!(shdr(ShdrField::Link, 3).link, 3);
    assert_eq!(shdr(ShdrField::Info, 4).info, 4);
    assert_eq!(shdr(ShdrField::Align, 0x10).align, 0x10);
    assert_eq!(shdr(ShdrField::Entsize, 5).entsize, 5);
}

#[test]
fn elf_malformed_knobs_without_a_target_change_nothing() {
    let plain = ElfBuilder::exec().section(text()).build();
    let same = |knob: Malformed| {
        let bytes = ElfBuilder::exec().section(text()).malformed(knob).build();
        assert_eq!(bytes, plain);
    };
    same(Malformed::Shdr(".nope".to_string(), ShdrField::Size, 1));
    same(Malformed::Dynamic(1, 2));
    same(Malformed::DropDynamicNull);
    same(Malformed::GnuHashOpenChain);
    same(Malformed::Truncate(usize::MAX));
    same(Malformed::Patch(1 << 40, vec![1, 2]));
    let stripped = ElfBuilder::exec().section(text()).strip_section_headers();
    let escaped = stripped.clone().malformed(Malformed::EscapeCounts).build();
    assert_eq!(escaped, stripped.build(), "no section 0 to hold the counts");
    let empty = ElfBuilder::exec().malformed(Malformed::Phdr(99, PhdrField::Type, 1));
    assert_eq!(empty.build().len(), ElfBuilder::exec().build().len());
}
