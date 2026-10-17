//! Tests of `ElfBuilder`.

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod elf_read;

use std::path::{Path, PathBuf};
use std::process::Command;

use elf_read::{Elf, Shdr};
use ghidorah_testkit::elf::consts::{
    DF_1_PIE, DT_FLAGS_1, DT_GNU_HASH, DT_HASH, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL,
    DT_NEEDED, DT_NULL, DT_PLTGOT, DT_PLTREL, DT_PLTRELSZ, DT_RELA, DT_RELR, DT_RELRSZ, DT_RUNPATH,
    DT_SONAME, DT_STRTAB, DT_SYMTAB, EM_X86_64, ET_DYN, ET_EXEC, PF_R, PF_W, PF_X, PT_DYNAMIC,
    PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD, PT_NOTE, R_X86_64_GLOB_DAT,
    R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS,
};
use ghidorah_testkit::elf::{
    self, Class, EhdrField, ElfBuilder, Endian, Fde, FixupKind, HashStyle, ImportKind, Loc,
    Malformed, PltStyle, Reloc, RelocTable, Section, ShdrField, Symbol,
};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::rng::fnv1a64;

const GOLDEN: &str = "tests/golden/elf_minimal.readelf.txt";
const READELF_ARGS: [&str; 5] = ["-W", "-h", "-l", "-S", "-s"];

fn golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN)
}

/// Returns the value after `label` in a readelf header line.
fn readelf_value<'a>(body: &'a str, label: &str) -> Option<&'a str> {
    body.lines()
        .find_map(|l| l.trim().strip_prefix(label))
        .map(|rest| rest.split_whitespace().next().unwrap_or(""))
}

fn parse_num(text: &str) -> u64 {
    text.strip_prefix("0x").map_or_else(
        || text.parse().unwrap_or(u64::MAX),
        |hex| u64::from_str_radix(hex, 16).unwrap_or(u64::MAX),
    )
}

/// Returns the section names of the readelf section table, without the null section.
fn readelf_section_names(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| {
            let (_, rest) = l.split_once("] ")?;
            if !l.trim_start().starts_with('[') {
                return None;
            }
            let name = rest.split_whitespace().next()?;
            name.starts_with('.').then(|| name.to_string())
        })
        .collect()
}

#[test]
fn elf_builder_minimal_matches_readelf_golden() {
    let bytes = elf::minimal().build();
    let read = golden::read(&golden_path());
    let Ok((header, body)) = read else {
        panic!("the readelf golden is readable: {read:?}");
    };
    assert_eq!(header.generator(), "testkit-elf-minimal");
    assert_eq!(
        header.field("bytes"),
        Some(bytes.len().to_string().as_str())
    );
    let fnv = format!("{:016x}", fnv1a64(&bytes));
    assert_eq!(
        header.field("fnv1a64"),
        Some(fnv.as_str()),
        "the golden comes from these exact bytes"
    );
    assert!(
        header
            .field("oracle")
            .is_some_and(|o| o.starts_with("readelf"))
    );
    let e = Elf::new(&bytes);
    assert_eq!(
        readelf_value(&body, "Entry point address:").map(parse_num),
        Some(e.e_entry())
    );
    assert_eq!(
        readelf_value(&body, "Number of program headers:").map(parse_num),
        Some(u64::from(e.e_phnum()))
    );
    assert_eq!(
        readelf_value(&body, "Number of section headers:").map(parse_num),
        Some(u64::from(e.e_shnum()))
    );
    let names: Vec<String> = e.shdrs().into_iter().skip(1).map(|s| s.name).collect();
    assert_eq!(readelf_section_names(&body), names);
    assert!(body.contains("_start"));
    assert!(!body.contains("Warning"), "readelf gave no warning");
}

fn readelf_version() -> Option<String> {
    let out = Command::new("readelf").arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?;
    first.split_whitespace().last().map(ToString::to_string)
}

fn readelf(bytes: &[u8], name: &str, args: &[&str]) -> String {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    let out = Command::new("readelf")
        .args(args)
        .arg(&path)
        .output()
        .unwrap_or_else(|e| panic!("run readelf: {e}"));
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    text
}

#[test]
#[ignore = "tier2"]
fn elf_builder_minimal_readelf_live() {
    let bytes = elf::minimal().build();
    let Some(version) = readelf_version() else {
        panic!("tier 2 needs readelf on PATH");
    };
    let header = Header::new("testkit-elf-minimal", "1")
        .with("oracle", &format!("readelf_{version}"))
        .with("args", &READELF_ARGS.join(","))
        .with("bytes", &bytes.len().to_string())
        .with("fnv1a64", &format!("{:016x}", fnv1a64(&bytes)));
    let text = readelf(&bytes, "elf_minimal.bin", &READELF_ARGS);
    golden::assert_text(&golden_path(), &header, &text);
}

fn full_builder() -> ElfBuilder {
    // main: push rbp; mov rbp, rsp; call puts@plt; call [rip + exit@got]; pop rbp; ret
    let code = [
        0x55, 0x48, 0x89, 0xe5, 0xe8, 0, 0, 0, 0, 0xff, 0x15, 0, 0, 0, 0, 0x5d, 0xc3, 0x90,
    ];
    let text = Section::code(".text", &code)
        .fixup(5, FixupKind::Rel32, Loc::Plt("puts".into()))
        .fixup(11, FixupKind::Rel32, Loc::Got("exit".into()));
    ElfBuilder::dyn_object()
        .interp("/lib64/ld-linux-x86-64.so.2")
        .section(text)
        .section(Section::rodata(".rodata", b"hello\0"))
        .section(Section::data(".data", &[0u8; 16]).fixup(0, FixupKind::Abs64, Loc::symbol("main")))
        .section(Section::bss(".bss", 64))
        .symbol(Symbol::func("main", Loc::section(".text", 0), 17))
        .symbol(Symbol::object("message", Loc::section(".rodata", 0), 6).local())
        .export(Symbol::func("main", Loc::section(".text", 0), 17))
        .import("puts", ImportKind::Plt)
        .import("printf", ImportKind::Plt)
        .import("exit", ImportKind::Got)
        .import("free", ImportKind::PltGot)
        .needed("libc.so.6")
        .runpath("$ORIGIN")
        .dt_flags_1(DF_1_PIE)
        .reloc(Reloc {
            table: RelocTable::Rela,
            at: Loc::section(".data", 8),
            kind: R_X86_64_RELATIVE,
            sym: None,
            addend: 0x40,
        })
        .relr(Loc::section(".data", 0))
        .build_id(&[0x11; 20])
        .x86_features(3)
        .fde(Fde::frame_pointer(Loc::symbol("main"), 17))
        .init_array(Loc::symbol("main"))
        .gnu_stack(false)
        .gnu_relro()
        .entry(Loc::symbol("main"))
}

#[test]
#[ignore = "tier2"]
fn elf_builder_full_readelf_clean() {
    let bytes = full_builder().build();
    let text = readelf(&bytes, "elf_full.bin", &["-W", "-a"]);
    let bad: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("Warning") || l.contains("Error") || l.contains("warning"))
        .collect();
    assert!(
        bad.is_empty(),
        "readelf complains:\n{}\n{text}",
        bad.join("\n")
    );
    let frames = readelf(&bytes, "elf_full_frames.bin", &["--debug-dump=frames"]);
    assert!(!frames.contains("Warning"), "{frames}");
    assert!(frames.contains("FDE"), "{frames}");
    let dynamic = readelf(&bytes, "elf_full_dyn.bin", &["-D", "-r", "-W"]);
    assert!(dynamic.contains("puts"), "{dynamic}");
    assert!(dynamic.contains("R_X86_64_JUMP_SLO"), "{dynamic}");
}

#[test]
fn elf_header_fields() {
    let (bytes, layout) = elf::minimal().build_with_layout();
    let e = Elf::new(&bytes);
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert_eq!(bytes[4], 2, "ELF64");
    assert_eq!(bytes[5], 1, "little-endian");
    assert_eq!(bytes[6], 1, "version 1");
    assert_eq!(e.e_type(), ET_EXEC);
    assert_eq!(e.e_machine(), EM_X86_64);
    assert_eq!(e.e_phoff(), 64);
    assert_eq!(e.e_phentsize(), 56);
    assert_eq!(e.e_shentsize(), 64);
    assert_eq!(Some(e.e_entry()), layout.symbols.get("_start").copied());
    assert_eq!(e.e_entry(), 0x40_0080);
    assert_eq!(layout.entry, e.e_entry());
    let names: Vec<String> = e.shdrs().into_iter().map(|s| s.name).collect();
    assert_eq!(names, ["", ".text", ".symtab", ".strtab", ".shstrtab"]);
    let syms = e.symbols(".symtab");
    assert_eq!(syms.len(), 2);
    assert_eq!(syms[1].0, "_start");
    assert_eq!(syms[1].1, e.e_entry());
}

#[test]
fn elf_header_only_elf32_and_big_endian() {
    let h32 = elf::header_only(Class::Elf32, Endian::Big, ET_EXEC, 8);
    assert_eq!(h32.len(), 52);
    assert_eq!(&h32[..4], b"\x7fELF");
    assert_eq!(h32[4], 1, "ELF32");
    assert_eq!(h32[5], 2, "big-endian");
    assert_eq!(&h32[16..18], &[0, 2], "e_type in big-endian");
    assert_eq!(&h32[18..20], &[0, 8], "e_machine in big-endian");
    assert_eq!(&h32[40..42], &[0, 52], "e_ehsize");
    let h64 = elf::header_only(Class::Elf64, Endian::Big, ET_DYN, EM_X86_64);
    assert_eq!(h64.len(), 64);
    assert_eq!(h64[4], 2);
    assert_eq!(h64[5], 2);
    assert_eq!(&h64[52..54], &[0, 64], "e_ehsize");
    let le32 = elf::header_only(Class::Elf32, Endian::Little, ET_EXEC, 3);
    assert_eq!(&le32[18..20], &[3, 0]);
}

fn load_covers(e: &Elf, s: &Shdr, base: u64) {
    let size = if s.sh_type == SHT_NOBITS {
        s.size
    } else {
        s.size.max(1)
    };
    let want = PF_R
        | if s.flags & SHF_WRITE != 0 { PF_W } else { 0 }
        | if s.flags & SHF_EXECINSTR != 0 {
            PF_X
        } else {
            0
        };
    let hit = e
        .phdrs()
        .into_iter()
        .find(|p| p.p_type == PT_LOAD && s.addr >= p.vaddr && s.addr + size <= p.vaddr + p.memsz);
    let Some(p) = hit else {
        panic!("no PT_LOAD covers {}", s.name);
    };
    assert_eq!(p.flags, want, "segment flags of {}", s.name);
    assert_eq!(
        p.vaddr - p.offset,
        base,
        "VA = base + offset for {}",
        s.name
    );
    if s.sh_type != SHT_NOBITS {
        assert_eq!(s.addr - base, s.offset, "{}", s.name);
    }
}

#[test]
fn elf_segments_cover_alloc_sections() {
    let (bytes, layout) = full_builder().build_with_layout();
    let e = Elf::new(&bytes);
    for s in e.shdrs().iter().filter(|s| s.flags & SHF_ALLOC != 0) {
        load_covers(&e, s, 0);
    }
    assert!(layout.section(".bss").is_some());
    let loads: Vec<_> = e
        .phdrs()
        .into_iter()
        .filter(|p| p.p_type == PT_LOAD)
        .collect();
    assert!(loads.len() >= 3, "R, RX and RW runs: {loads:?}");
    assert_eq!(loads[0].offset, 0, "the first PT_LOAD maps the headers");
    let last = loads.last().copied();
    assert!(
        last.is_some_and(|p| p.memsz > p.filesz),
        "the .bss tail is zero-fill"
    );
    let types: Vec<u32> = e.phdrs().iter().map(|p| p.p_type).collect();
    for t in [
        PT_INTERP,
        PT_DYNAMIC,
        PT_NOTE,
        PT_GNU_EH_FRAME,
        PT_GNU_STACK,
        PT_GNU_RELRO,
    ] {
        assert!(
            types.contains(&t),
            "program header type {t:#x} is present: {types:x?}"
        );
    }
    assert_eq!(usize::from(e.e_phnum()), types.len());
    assert_eq!(layout.phnum, e.e_phnum());
    let stack = e.phdrs().into_iter().find(|p| p.p_type == PT_GNU_STACK);
    assert_eq!(stack.map(|p| p.flags), Some(PF_R | PF_W));
}

#[test]
fn elf_exec_segments_with_base() {
    let b = ElfBuilder::exec()
        .section(Section::code(".text", &[0xc3]))
        .section(Section::rodata(".rodata", b"abc"))
        .section(Section::data(".data", &[1, 2, 3, 4]))
        .section(Section::bss(".bss", 32));
    let bytes = b.build();
    let e = Elf::new(&bytes);
    for s in e.shdrs().iter().filter(|s| s.flags & SHF_ALLOC != 0) {
        load_covers(&e, s, 0x40_0000);
    }
    assert_eq!(
        e.e_entry(),
        e.section(".text").map_or(0, |s| s.addr),
        "entry defaults to .text"
    );
}

fn rela_entries(e: &Elf, name: &str) -> Vec<(u64, u32, u32, i64)> {
    let Some(s) = e.section(name) else {
        return Vec::new();
    };
    (0..s.size / 24)
        .map(|i| {
            let o = s.offset + i * 24;
            let info = e.u64(o + 8);
            let addend = i64::from_le_bytes(e.u64(o + 16).to_le_bytes());
            (
                e.u64(o),
                u32::try_from(info >> 32).unwrap_or(u32::MAX),
                u32::try_from(info & 0xffff_ffff).unwrap_or(u32::MAX),
                addend,
            )
        })
        .collect()
}

fn dynsym_name(e: &Elf, index: u32) -> String {
    let syms = e.symbols(".dynsym");
    syms.get(usize::try_from(index).unwrap_or(usize::MAX))
        .map(|s| s.0.clone())
        .unwrap_or_default()
}

#[test]
fn elf_plt_stubs_name_slots_through_relocations() {
    let (bytes, layout) = full_builder().build_with_layout();
    let e = Elf::new(&bytes);
    let plt_rel = rela_entries(&e, ".rela.plt");
    assert_eq!(plt_rel.len(), 2);
    for name in ["puts", "printf"] {
        let stub = layout.plt[name];
        let off = e.va_to_off(stub).unwrap_or(u64::MAX);
        assert_eq!(
            &bytes[usize::try_from(off).unwrap_or(0)..][..2],
            &[0xff, 0x25],
            "{name}"
        );
        let disp = e.i32(off + 2);
        let slot = (stub + 6).wrapping_add_signed(i64::from(disp));
        assert_eq!(slot, layout.got[name], "slot of {name}");
        let rel = plt_rel.iter().find(|r| r.0 == slot);
        let Some(rel) = rel else {
            panic!("a JUMP_SLOT relocation names the slot of {name}");
        };
        assert_eq!(rel.2, R_X86_64_JUMP_SLOT);
        assert_eq!(dynsym_name(&e, rel.1), name);
    }
    let dyn_rel = rela_entries(&e, ".rela.dyn");
    let glob: Vec<String> = dyn_rel
        .iter()
        .filter(|r| r.2 == R_X86_64_GLOB_DAT)
        .map(|r| dynsym_name(&e, r.1))
        .collect();
    assert_eq!(glob, ["exit", "free"]);
    assert!(
        dyn_rel
            .iter()
            .any(|r| r.2 == R_X86_64_RELATIVE && r.3 == 0x40)
    );
    // `.plt.got`: ff 25 disp32 66 90
    let stub = layout.plt_got["free"];
    let off = usize::try_from(e.va_to_off(stub).unwrap_or(0)).unwrap_or(0);
    assert_eq!(&bytes[off..off + 2], &[0xff, 0x25]);
    assert_eq!(&bytes[off + 6..off + 8], &[0x66, 0x90]);
    // The code fixups reach the stub and the slot.
    let text = e.section(".text").unwrap_or_else(|| panic!("no .text"));
    let call = text.addr + 9;
    let rel32 = e.i32(text.offset + 5);
    assert_eq!(
        call.wrapping_add_signed(i64::from(rel32)),
        layout.plt["puts"]
    );
    let next = text.addr + 15;
    let disp = e.i32(text.offset + 11);
    assert_eq!(
        next.wrapping_add_signed(i64::from(disp)),
        layout.got["exit"]
    );
    let data = e.section(".data").unwrap_or_else(|| panic!("no .data"));
    assert_eq!(
        e.u64(data.offset),
        layout.symbols["main"],
        "the Abs64 fixup"
    );
}

#[test]
fn elf_plt_sec_ibt_stubs() {
    let b = ElfBuilder::exec()
        .section(Section::code(".text", &[0xc3]))
        .import("puts", ImportKind::Plt)
        .plt_style(PltStyle::Ibt)
        .needed("libc.so.6");
    let (bytes, layout) = b.build_with_layout();
    let e = Elf::new(&bytes);
    let sec = e
        .section(".plt.sec")
        .unwrap_or_else(|| panic!("no .plt.sec"));
    let stub = layout.plt["puts"];
    assert_eq!(stub, sec.addr, "the import address is the .plt.sec stub");
    let off = usize::try_from(sec.offset).unwrap_or(0);
    assert_eq!(
        &bytes[off..off + 7],
        &[0xf3, 0x0f, 0x1e, 0xfa, 0xf2, 0xff, 0x25]
    );
    let disp = e.i32(sec.offset + 7);
    assert_eq!(
        (stub + 11).wrapping_add_signed(i64::from(disp)),
        layout.got["puts"]
    );
    let plt = e.section(".plt").unwrap_or_else(|| panic!("no .plt"));
    let lazy = usize::try_from(plt.offset + 16).unwrap_or(0);
    assert_eq!(
        &bytes[lazy..lazy + 5],
        &[0xf3, 0x0f, 0x1e, 0xfa, 0x68],
        "IBT lazy entry"
    );
}

fn gnu_hash_count(e: &Elf, s: &Shdr) -> Option<u64> {
    let nbuckets = u64::from(e.u32(s.offset));
    let symoffset = u64::from(e.u32(s.offset + 4));
    let bloom = u64::from(e.u32(s.offset + 8));
    let buckets = s.offset + 16 + 8 * bloom;
    let chains = buckets + 4 * nbuckets;
    let max = (0..nbuckets)
        .map(|i| u64::from(e.u32(buckets + 4 * i)))
        .max()?;
    if max == 0 {
        return Some(symoffset);
    }
    let mut i = max;
    loop {
        let at = chains + 4 * (i - symoffset);
        if at + 4 > s.offset + s.size {
            return None;
        }
        if e.u32(at) & 1 == 1 {
            return Some(i + 1);
        }
        i += 1;
    }
}

fn exports_builder(style: HashStyle) -> ElfBuilder {
    let mut b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3; 64]))
        .hash(style)
        .soname("libt.so.1")
        .import("puts", ImportKind::Plt)
        .import("malloc", ImportKind::Plt);
    for (i, name) in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta"]
        .iter()
        .enumerate()
    {
        let at = Loc::section(".text", u64::try_from(i).unwrap_or(0) * 8);
        b = b.export(Symbol::func(name, at, 8));
    }
    b
}

#[test]
fn elf_gnu_hash_gives_the_dynamic_symbol_count() {
    let bytes = exports_builder(HashStyle::Gnu).build();
    let e = Elf::new(&bytes);
    let dynsym = e.section(".dynsym").unwrap_or_else(|| panic!("no .dynsym"));
    let gh = e
        .section(".gnu.hash")
        .unwrap_or_else(|| panic!("no .gnu.hash"));
    assert_eq!(gnu_hash_count(&e, &gh), Some(dynsym.size / 24));
    assert_eq!(e.dyn_value(DT_GNU_HASH), Some(gh.addr));
    assert_eq!(e.dyn_value(DT_HASH), None);
    let names: Vec<String> = e.symbols(".dynsym").into_iter().map(|s| s.0).collect();
    assert_eq!(names.len(), 10);
    assert_eq!(&names[..3], ["", "puts", "malloc"], "imports come first");
}

#[test]
fn elf_sysv_hash_nchain_is_the_symbol_count() {
    let bytes = exports_builder(HashStyle::Both).build();
    let e = Elf::new(&bytes);
    let dynsym = e.section(".dynsym").unwrap_or_else(|| panic!("no .dynsym"));
    let h = e.section(".hash").unwrap_or_else(|| panic!("no .hash"));
    assert_eq!(u64::from(e.u32(h.offset + 4)), dynsym.size / 24);
    assert_eq!(e.dyn_value(DT_HASH), Some(h.addr));
    assert!(e.dyn_value(DT_GNU_HASH).is_some());
    let none = exports_builder(HashStyle::None).build();
    let e = Elf::new(&none);
    assert!(e.section(".hash").is_none() && e.section(".gnu.hash").is_none());
}

fn relr_decode(entries: &[u64]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut base = 0u64;
    for &entry in entries {
        if entry & 1 == 0 {
            out.push(entry);
            base = entry + 8;
        } else {
            let mut bits = entry >> 1;
            let mut k = 0u64;
            while bits != 0 {
                if bits & 1 == 1 {
                    out.push(base + k * 8);
                }
                bits >>= 1;
                k += 1;
            }
            base += 63 * 8;
        }
    }
    out
}

#[test]
fn elf_relr_encoding_roundtrip() {
    let offsets = [0u64, 8, 16, 40, 64, 504, 512, 520, 1000, 2048];
    let mut b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3]))
        .section(Section::data(".data", &[0u8; 2056]));
    for off in offsets {
        b = b.relr(Loc::section(".data", off));
    }
    let (bytes, layout) = b.build_with_layout();
    let e = Elf::new(&bytes);
    let relr = e
        .section(".relr.dyn")
        .unwrap_or_else(|| panic!("no .relr.dyn"));
    let entries: Vec<u64> = (0..relr.size / 8)
        .map(|i| e.u64(relr.offset + i * 8))
        .collect();
    let data = layout.section(".data").map_or(0, |s| s.addr);
    let want: Vec<u64> = offsets.iter().map(|o| data + o).collect();
    assert_eq!(relr_decode(&entries), want);
    assert!(entries.len() < offsets.len(), "bitmaps pack the places");
    assert_eq!(e.dyn_value(DT_RELR), Some(relr.addr));
    assert_eq!(e.dyn_value(DT_RELRSZ), Some(relr.size));
}

#[test]
fn elf_notes_build_id_and_property() {
    let (bytes, _) = full_builder().build_with_layout();
    let e = Elf::new(&bytes);
    let notes: Vec<_> = e
        .phdrs()
        .into_iter()
        .filter(|p| p.p_type == PT_NOTE)
        .collect();
    assert_eq!(notes.len(), 2);
    let id = e
        .section(".note.gnu.build-id")
        .unwrap_or_else(|| panic!("no build-id"));
    assert_eq!(e.u32(id.offset), 4, "namesz");
    assert_eq!(e.u32(id.offset + 4), 20, "descsz");
    assert_eq!(e.u32(id.offset + 8), 3, "NT_GNU_BUILD_ID");
    assert_eq!(
        &bytes[usize::try_from(id.offset + 12).unwrap_or(0)..][..4],
        b"GNU\0"
    );
    assert_eq!(
        &bytes[usize::try_from(id.offset + 16).unwrap_or(0)..][..20],
        &[0x11; 20]
    );
    let prop = e
        .section(".note.gnu.property")
        .unwrap_or_else(|| panic!("no property"));
    assert_eq!(prop.align, 8);
    assert_eq!(e.u32(prop.offset + 16), 0xc000_0002);
    assert_eq!(e.u32(prop.offset + 24), 3, "IBT and SHSTK");
    let p = notes.iter().find(|p| p.offset == prop.offset);
    assert_eq!(p.map(|p| p.align), Some(8));
}

#[test]
fn elf_eh_frame_fde_range_and_header() {
    let (bytes, layout) = full_builder().build_with_layout();
    let e = Elf::new(&bytes);
    let eh = e
        .section(".eh_frame")
        .unwrap_or_else(|| panic!("no .eh_frame"));
    let cie_len = u64::from(e.u32(eh.offset));
    assert_eq!(e.u32(eh.offset + 4), 0, "CIE id");
    assert_eq!(
        bytes[usize::try_from(eh.offset + 8).unwrap_or(0)],
        1,
        "CIE version"
    );
    let fde = eh.offset + 4 + cie_len;
    let fde_len = u64::from(e.u32(fde));
    assert!(fde_len > 0);
    assert_eq!(
        u64::from(e.u32(fde + 4)),
        fde + 4 - eh.offset,
        "CIE pointer"
    );
    let pc_field = eh.addr + (fde + 8 - eh.offset);
    let pc_begin = pc_field.wrapping_add_signed(i64::from(e.i32(fde + 8)));
    assert_eq!(pc_begin, layout.symbols["main"]);
    assert_eq!(e.u32(fde + 12), 17, "pc_range");
    assert_eq!(e.u32(fde + 4 + fde_len), 0, "the terminator");
    let hdr = e
        .section(".eh_frame_hdr")
        .unwrap_or_else(|| panic!("no .eh_frame_hdr"));
    let off = usize::try_from(hdr.offset).unwrap_or(0);
    assert_eq!(&bytes[off..off + 4], &[1, 0x1b, 0x03, 0x3b]);
    let ptr = (hdr.addr + 4).wrapping_add_signed(i64::from(e.i32(hdr.offset + 4)));
    assert_eq!(ptr, eh.addr, "eh_frame_ptr");
    assert_eq!(e.u32(hdr.offset + 8), 1, "fde_count");
    let p = e.phdrs().into_iter().find(|p| p.p_type == PT_GNU_EH_FRAME);
    assert_eq!(p.map(|p| p.vaddr), Some(hdr.addr));
}

fn dynstr(e: &Elf, value: u64) -> String {
    let strtab = e
        .dyn_value(DT_STRTAB)
        .and_then(|va| e.va_to_off(va))
        .unwrap_or(0);
    e.cstr(strtab + value)
}

#[test]
fn elf_dynamic_tags() {
    let (bytes, layout) = full_builder().build_with_layout();
    let e = Elf::new(&bytes);
    let entries = e.dynamic();
    assert_eq!(entries.last().map(|t| t.0), Some(DT_NULL));
    let needed = e.dyn_value(DT_NEEDED).map(|v| dynstr(&e, v));
    assert_eq!(needed.as_deref(), Some("libc.so.6"));
    let runpath = e.dyn_value(DT_RUNPATH).map(|v| dynstr(&e, v));
    assert_eq!(runpath.as_deref(), Some("$ORIGIN"));
    assert_eq!(
        e.dyn_value(DT_SYMTAB),
        layout.section(".dynsym").map(|s| s.addr)
    );
    assert_eq!(
        e.dyn_value(DT_STRTAB),
        layout.section(".dynstr").map(|s| s.addr)
    );
    assert_eq!(
        e.dyn_value(DT_JMPREL),
        layout.section(".rela.plt").map(|s| s.addr)
    );
    assert_eq!(e.dyn_value(DT_PLTRELSZ), Some(48));
    assert_eq!(e.dyn_value(DT_PLTREL), Some(DT_RELA));
    assert_eq!(
        e.dyn_value(DT_PLTGOT),
        layout.section(".got.plt").map(|s| s.addr)
    );
    assert_eq!(e.dyn_value(DT_FLAGS_1), Some(DF_1_PIE));
    assert_eq!(
        e.dyn_value(DT_INIT_ARRAY),
        layout.section(".init_array").map(|s| s.addr)
    );
    assert_eq!(e.dyn_value(DT_INIT_ARRAYSZ), Some(8));
    let init = layout.section(".init_array").map_or(0, |s| s.offset);
    assert_eq!(e.u64(init), layout.symbols["main"]);
    let interp = e.section(".interp").unwrap_or_else(|| panic!("no .interp"));
    assert_eq!(e.cstr(interp.offset), "/lib64/ld-linux-x86-64.so.2");
    let so = exports_builder(HashStyle::Gnu).build();
    let e = Elf::new(&so);
    let soname = e.dyn_value(DT_SONAME).map(|v| dynstr(&e, v));
    assert_eq!(soname.as_deref(), Some("libt.so.1"));
}

#[test]
fn elf_strip_section_headers() {
    let bytes = full_builder().strip_section_headers().build();
    let e = Elf::new(&bytes);
    assert_eq!(e.e_shoff(), 0);
    assert_eq!(e.e_shnum(), 0);
    assert_eq!(e.e_shstrndx(), 0);
    assert!(e.dyn_value(DT_JMPREL).is_some(), "the dynamic view stays");
    assert!(bytes.len() < full_builder().build().len());
}

#[test]
fn elf_malformed_knobs_change_fields() {
    let base = full_builder();
    let plain = base.build();
    let real = Elf::new(&plain);
    let bad_magic = base.clone().malformed(Malformed::BadMagic).build();
    assert_ne!(bad_magic[0], 0x7f);
    let cut = base.clone().malformed(Malformed::Truncate(40)).build();
    assert_eq!(cut.len(), 40);
    let small = base
        .clone()
        .malformed(Malformed::Ehdr(EhdrField::Phentsize, 32))
        .build();
    assert_eq!(Elf::new(&small).e_phentsize(), 32);
    let zero = base
        .clone()
        .malformed(Malformed::Shdr(".dynsym".into(), ShdrField::Entsize, 0))
        .build();
    assert_eq!(
        Elf::new(&zero).section(".dynsym").map(|s| s.entsize),
        Some(0)
    );
    let patched = base
        .clone()
        .malformed(Malformed::Patch(8, vec![0xaa, 0xbb]))
        .build();
    assert_eq!(&patched[8..10], &[0xaa, 0xbb]);
    let escaped = base.clone().malformed(Malformed::EscapeCounts).build();
    let e = Elf::new(&escaped);
    assert_eq!(e.e_phnum(), 0xffff);
    assert_eq!(e.e_shnum(), 0);
    assert_eq!(e.e_shstrndx(), 0xffff);
    let s0 = e.e_shoff();
    assert_eq!(
        e.u32(s0 + 44),
        u32::from(real.e_phnum()),
        "sh_info holds e_phnum"
    );
    assert_eq!(
        e.u64(s0 + 32),
        u64::from(real.e_shnum()),
        "sh_size holds e_shnum"
    );
    assert_eq!(
        e.u32(s0 + 40),
        u32::from(real.e_shstrndx()),
        "sh_link holds e_shstrndx"
    );
    let open = base.clone().malformed(Malformed::DropDynamicNull).build();
    assert!(Elf::new(&open).dynamic().iter().all(|t| t.0 != DT_NULL));
    let set = base.malformed(Malformed::Dynamic(DT_PLTRELSZ, 0)).build();
    assert_eq!(Elf::new(&set).dyn_value(DT_PLTRELSZ), Some(0));
    let hashed = exports_builder(HashStyle::Gnu)
        .malformed(Malformed::GnuHashOpenChain)
        .build();
    let e = Elf::new(&hashed);
    let gh = e
        .section(".gnu.hash")
        .unwrap_or_else(|| panic!("no .gnu.hash"));
    assert_eq!(
        gnu_hash_count(&e, &gh),
        None,
        "the chain runs off the table"
    );
}

#[test]
fn elf_malformed_variants_catalog() {
    let codes = [
        "E_OOB",
        "E_OVERFLOW",
        "E_BAD_MAGIC",
        "E_LIMIT",
        "E_LOOP",
        "E_BAD_ALIGN",
        "E_BAD_ENTSIZE",
        "E_UNSUPPORTED_RELOC",
        "E_CFA_OPCODE",
    ];
    let variants = elf::malformed_variants();
    assert!(variants.len() >= 12, "{} variants", variants.len());
    let mut names: Vec<&str> = variants.iter().map(|v| v.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), variants.len(), "names are unique");
    for code in codes {
        assert!(
            variants.iter().any(|v| v.expect == code),
            "one variant expects {code}"
        );
    }
    for v in &variants {
        assert!(codes.contains(&v.expect), "{} expects a known code", v.name);
        assert!(v.bytes.len() >= 4 || v.expect == "E_OOB", "{}", v.name);
    }
    assert_eq!(
        elf::malformed_variants(),
        variants,
        "the catalog is deterministic"
    );
}
