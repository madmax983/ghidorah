//! Behavior on `ElfBuilder` files: the dynamic view, hash counts, RELR, `SHN_XINDEX`,
//! versions, entry arrays and other machines.

use ghidorah_base::{BinText, DiagCode};
use ghidorah_loader::{
    Arch, Binary, EntryKind, RelocForm, RelocSource, RelocType, SymBind, SymKind, SymTable, SymVis,
};
use ghidorah_testkit::elf::consts::{DT_FLAGS, DT_FLAGS_1, DT_RPATH, R_X86_64_RELATIVE};
use ghidorah_testkit::elf::{
    ElfBuilder, HashStyle, ImportKind, Loc, Malformed, Reloc, RelocTable, Section, ShdrField,
    Symbol,
};

use crate::support::load_ok;

fn section<'a>(b: &'a Binary, name: &str) -> &'a ghidorah_loader::Section {
    b.sections
        .iter()
        .find(|s| s.name.as_bytes() == name.as_bytes())
        .unwrap_or_else(|| panic!("no section {name}"))
}

fn exports_builder(hash: HashStyle) -> ElfBuilder {
    ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3; 32]))
        .export(Symbol::func("alpha", Loc::section(".text", 0), 4))
        .export(Symbol::func("beta", Loc::section(".text", 4), 4))
        .export(Symbol::object("gamma", Loc::section(".text", 8), 4).weak())
        .export(Symbol::func("delta", Loc::section(".text", 12), 4))
        .import("puts", ImportKind::Plt)
        .needed("libc.so.6")
        .hash(hash)
}

#[test]
fn dynamic_view_symbol_count_from_each_hash() {
    for hash in [
        HashStyle::Sysv,
        HashStyle::Gnu,
        HashStyle::Both,
        HashStyle::None,
    ] {
        let full = load_ok(&exports_builder(hash).build()).0;
        let bare = load_ok(&exports_builder(hash).strip_section_headers().build()).0;
        let names = |b: &Binary| -> Vec<Vec<u8>> {
            b.symbols_of(SymTable::Dynsym)
                .map(|s| s.name.as_bytes().to_vec())
                .collect()
        };
        assert_eq!(
            names(&full).len(),
            6,
            "{hash:?}: null, puts and four exports"
        );
        assert_eq!(names(&bare), names(&full), "{hash:?}");
        assert!(
            bare.diagnostics.is_empty(),
            "{hash:?}: {:?}",
            bare.diagnostics
        );
        assert_eq!(bare.exports, full.exports, "{hash:?}");
        assert_eq!(bare.exports.len(), 4, "{hash:?}");
    }
}

#[test]
fn symbol_fields() {
    let b = load_ok(&exports_builder(HashStyle::Gnu).build()).0;
    let gamma = b
        .symbols_of(SymTable::Dynsym)
        .find(|s| s.name.as_bytes() == b"gamma")
        .expect("gamma");
    assert_eq!(gamma.kind, SymKind::Object);
    assert_eq!(gamma.bind, SymBind::Weak);
    assert_eq!(gamma.vis, SymVis::Default);
    assert_eq!(gamma.size, 4);
    assert_eq!(gamma.shndx, section(&b, ".text").index);
    let puts = b
        .symbols_of(SymTable::Dynsym)
        .find(|s| s.name.as_bytes() == b"puts")
        .expect("puts");
    assert_eq!(
        (puts.kind, puts.bind, puts.shndx),
        (SymKind::Func, SymBind::Global, 0)
    );
    assert!(
        b.exports
            .iter()
            .all(|e| e.name.as_ref().is_some_and(|n| n.as_bytes() != b"puts"))
    );
}

#[test]
fn dynamic_view_strings() {
    let bytes = exports_builder(HashStyle::Gnu)
        .needed("libm.so.6")
        .soname("libz.so.1")
        .rpath("/opt/r")
        .runpath("/opt/rp")
        .strip_section_headers()
        .build();
    let b = load_ok(&bytes).0;
    let libs: Vec<&[u8]> = b.libraries.iter().map(BinText::as_bytes).collect();
    assert_eq!(libs, vec![&b"libc.so.6"[..], b"libm.so.6"]);
    assert_eq!(
        b.identity.soname.as_ref().map(BinText::as_bytes),
        Some(&b"libz.so.1"[..])
    );
    assert_eq!(
        b.rpath.as_ref().map(BinText::as_bytes),
        Some(&b"/opt/r"[..])
    );
    assert_eq!(
        b.runpath.as_ref().map(BinText::as_bytes),
        Some(&b"/opt/rp"[..])
    );
    assert_eq!(
        b.dynamic.last().map(|e| e.tag),
        Some(0),
        "the table ends with DT_NULL"
    );
    assert!(b.dyn_value(5).is_some(), "DT_STRTAB");
    assert_eq!(b.dyn_value(0x1234), None);
}

#[test]
fn relr_expands_to_relative() {
    let places = [0u64, 8, 24, 8 * 70, 8 * 71];
    let build = |strip: bool| {
        let mut b = ElfBuilder::dyn_object()
            .section(Section::code(".text", &[0xc3]))
            .section(Section::data(".data", &[0u8; 8 * 80]))
            .force_dynamic();
        for p in places {
            b = b.relr(Loc::section(".data", p));
        }
        if strip {
            b = b.strip_section_headers();
        }
        b.build_with_layout()
    };
    for strip in [false, true] {
        let (bytes, layout) = build(strip);
        let data = layout.section(".data").expect(".data").addr;
        let b = load_ok(&bytes).0;
        let relr: Vec<_> = b
            .relocs
            .iter()
            .filter(|r| r.form == RelocForm::Relr)
            .collect();
        let offsets: Vec<u64> = relr.iter().map(|r| r.offset).collect();
        let want: Vec<u64> = places.iter().map(|p| data + p).collect();
        assert_eq!(offsets, want, "strip {strip}");
        for r in relr {
            assert_eq!(r.kind, RelocType(R_X86_64_RELATIVE));
            assert_eq!(r.sym, None);
            assert_eq!(r.addend, 0);
            let dynamic = matches!(r.source, RelocSource::DynRelr);
            assert_eq!(dynamic, strip);
        }
        assert!(b.diagnostics.is_empty(), "{:?}", b.diagnostics);
    }
}

#[test]
fn rel_and_rela_fields() {
    let bytes = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3]))
        .section(Section::data(".data", &[0u8; 16]))
        .import("puts", ImportKind::Got)
        .reloc(Reloc {
            table: RelocTable::Rela,
            at: Loc::section(".data", 0),
            kind: R_X86_64_RELATIVE,
            sym: None,
            addend: -0x20,
        })
        .reloc(Reloc {
            table: RelocTable::Rel,
            at: Loc::section(".data", 8),
            kind: 1,
            sym: Some("puts".to_string()),
            addend: 0,
        })
        .build();
    let b = load_ok(&bytes).0;
    let rela = b.relocs.iter().find(|r| r.addend == -0x20).expect("RELA");
    assert_eq!((rela.form, rela.sym), (RelocForm::Rela, None));
    let rel = b
        .relocs
        .iter()
        .find(|r| r.form == RelocForm::Rel)
        .expect("REL");
    let puts = b
        .symbols_of(SymTable::Dynsym)
        .find(|s| s.name.as_bytes() == b"puts")
        .expect("puts");
    assert_eq!(rel.sym, Some(puts.index));
    assert_eq!(rel.sym_table, SymTable::Dynsym);
    assert_eq!(rel.kind.x86_64_name(), Some("R_X86_64_64"));
    assert_eq!(RelocType(42).x86_64_name(), Some("R_X86_64_REX_GOTPCRELX"));
    assert_eq!(RelocType(0x7777).x86_64_name(), None);
}

#[test]
fn xindex_resolves_through_symtab_shndx() {
    let base = |shndx: &[u8]| {
        ElfBuilder::exec()
            .section(Section::code(".text", &[0xc3; 8]))
            .section(
                Section::new(".symtab_shndx", 18, 0, shndx)
                    .align(4)
                    .entsize(4),
            )
            .symbol(Symbol::func("f", Loc::section(".text", 0), 1))
            .symbol(Symbol::func("g", Loc::section(".text", 4), 1))
    };
    let first = load_ok(&base(&[0u8; 12]).build()).0;
    let symtab = section(&first, ".symtab").clone();
    let text = section(&first, ".text").index;
    let g = first
        .symbols_of(SymTable::Symtab)
        .find(|s| s.name.as_bytes() == b"g")
        .expect("g")
        .clone();
    let count = usize::try_from(symtab.size / 24).expect("count");
    let mut shndx = vec![0u8; 4 * count];
    let at = 4 * g.index as usize;
    shndx[at..at + 4].copy_from_slice(&text.to_le_bytes());
    let entry = symtab.file_off + 24 * u64::from(g.index);
    let bytes = base(&shndx)
        .malformed(Malformed::Patch(
            entry + 6,
            0xffffu16.to_le_bytes().to_vec(),
        ))
        .malformed(Malformed::Shdr(
            ".symtab_shndx".to_string(),
            ShdrField::Link,
            u64::from(symtab.index),
        ))
        .build();
    let b = load_ok(&bytes).0;
    let got = b
        .symbols_of(SymTable::Symtab)
        .find(|s| s.name.as_bytes() == b"g")
        .expect("g");
    assert_eq!(
        got.shndx, text,
        "SHN_XINDEX gives the index of SHT_SYMTAB_SHNDX"
    );
}

/// The file offset of the first dynamic entry with `tag`.
fn dyn_entry_offset(b: &Binary, bytes: &[u8], tag: u64) -> u64 {
    let d = section(b, ".dynamic");
    (0..d.size / 16)
        .map(|i| d.file_off + 16 * i)
        .find(|&at| {
            let at = usize::try_from(at).expect("offset");
            bytes[at..at + 8] == tag.to_le_bytes()
        })
        .expect("dynamic tag")
}

#[test]
fn version_definitions_name_defined_symbols() {
    let build = |versym: &[u8], verdef: &[u8]| {
        exports_builder(HashStyle::Gnu)
            .soname("libx.so")
            .runpath("LIBX_1.0")
            .dt_flags(1)
            .dt_flags_1(1)
            .rpath("r")
            .section(Section::rodata(".gnu.version", versym).align(2))
            .section(Section::rodata(".gnu.version_d", verdef).align(8))
    };
    let probe_versym = vec![0u8; 12];
    let probe_verdef = vec![0u8; 56];
    let (bytes0, _) = build(&probe_versym, &probe_verdef).build_with_layout();
    let first = load_ok(&bytes0).0;
    let dynstr = section(&first, ".dynstr").clone();
    let strs = &bytes0[usize::try_from(dynstr.file_off).expect("off")..]
        [..usize::try_from(dynstr.size).expect("size")];
    let find = |s: &[u8]| -> u32 {
        let mut needle = s.to_vec();
        needle.push(0);
        let at = strs
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .expect("string in .dynstr");
        u32::try_from(at).expect("offset")
    };
    let mut versym = Vec::new();
    for s in first.symbols_of(SymTable::Dynsym) {
        let v: u16 = match s.name.as_bytes() {
            b"alpha" => 2,
            b"beta" => 0x8002,
            b"gamma" => 1,
            _ => 0,
        };
        versym.extend_from_slice(&v.to_le_bytes());
    }
    let mut verdef = Vec::new();
    for (flags, ndx, name, next) in [
        (1u16, 1u16, find(b"libx.so"), 28u32),
        (0, 2, find(b"LIBX_1.0"), 0),
    ] {
        for half in [1u16, flags, ndx, 1] {
            verdef.extend_from_slice(&half.to_le_bytes());
        }
        for word in [0u32, 20, next, name, 0] {
            verdef.extend_from_slice(&word.to_le_bytes());
        }
    }
    let (bytes1, layout) = build(&versym, &verdef).build_with_layout();
    let vs = layout.section(".gnu.version").expect("versym").addr;
    let vd = layout.section(".gnu.version_d").expect("verdef").addr;
    let patch = |tag: u64, new_tag: u64, value: u64| {
        let at = dyn_entry_offset(&first, &bytes1, tag);
        let mut entry = new_tag.to_le_bytes().to_vec();
        entry.extend_from_slice(&value.to_le_bytes());
        Malformed::Patch(at, entry)
    };
    let bytes = build(&versym, &verdef)
        .malformed(patch(DT_FLAGS, 0x6fff_fff0, vs))
        .malformed(patch(DT_FLAGS_1, 0x6fff_fffc, vd))
        .malformed(patch(DT_RPATH, 0x6fff_fffd, 2))
        .build();
    let b = load_ok(&bytes).0;
    let version = |name: &[u8]| {
        b.symbols_of(SymTable::Dynsym)
            .find(|s| s.name.as_bytes() == name)
            .expect("symbol")
            .version
            .clone()
    };
    let alpha = version(b"alpha").expect("alpha has a version");
    assert_eq!(alpha.name.as_bytes(), b"LIBX_1.0");
    assert_eq!((alpha.index, alpha.hidden, alpha.needed), (2, false, false));
    let beta = version(b"beta").expect("beta has a version");
    assert_eq!((beta.index, beta.hidden, beta.needed), (2, true, false));
    assert_eq!(version(b"gamma"), None, "index 1 is the base version");
    assert_eq!(version(b"delta"), None, "index 0 is local");
    assert!(b.diagnostics.is_empty(), "{:?}", b.diagnostics);
}

#[test]
fn entry_arrays_without_dynamic() {
    let (bytes, layout) = ElfBuilder::exec()
        .section(Section::code(".text", &[0xc3; 16]))
        .symbol(Symbol::func("a", Loc::section(".text", 0), 1))
        .symbol(Symbol::func("b", Loc::section(".text", 4), 1))
        .symbol(Symbol::func("c", Loc::section(".text", 8), 1))
        .init_array(Loc::symbol("a"))
        .fini_array(Loc::symbol("b"))
        .preinit_array(Loc::symbol("c"))
        .entry(Loc::symbol("a"))
        .build_with_layout();
    let b = load_ok(&bytes).0;
    let at = |n: &str| layout.symbols[n];
    let mut got: Vec<(u64, EntryKind)> = b.entry_points.iter().map(|e| (e.addr, e.kind)).collect();
    got.sort();
    let mut want = vec![
        (at("a"), EntryKind::Entry),
        (at("a"), EntryKind::InitArray),
        (at("b"), EntryKind::FiniArray),
        (at("c"), EntryKind::PreinitArray),
    ];
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn other_machine_loads_for_survey() {
    let bytes = ElfBuilder::exec()
        .machine(183)
        .section(Section::code(".text", &[0xc0, 0x03, 0x5f, 0xd6]))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 4))
        .build();
    let b = load_ok(&bytes).0;
    assert_eq!(b.arch, Arch::Other(183));
    assert_eq!(b.arch.to_string(), "other:183");
    assert!(!b.arch.is_x86_64());
    assert_eq!(Arch::X86_64.to_string(), "x86_64");
    assert!(
        b.symbols_of(SymTable::Symtab)
            .any(|s| s.name.as_bytes() == b"f")
    );
}

#[test]
fn bad_section_tables_give_diagnostics() {
    let base = || {
        ElfBuilder::exec()
            .section(Section::code(".text", &[0xc3; 4]))
            .symbol(Symbol::func("f", Loc::section(".text", 0), 4))
    };
    let codes = |m: Malformed| -> Vec<DiagCode> {
        let b = load_ok(&base().malformed(m).build()).0;
        b.diagnostics.iter().map(|d| d.code).collect()
    };
    let entsize = codes(Malformed::Shdr(".symtab".into(), ShdrField::Entsize, 16));
    assert_eq!(entsize, vec![DiagCode::BadEntsize]);
    let link = codes(Malformed::Shdr(".symtab".into(), ShdrField::Link, 0x999));
    assert_eq!(
        link,
        vec![DiagCode::Oob],
        "a string table index past the table"
    );
    let past = codes(Malformed::Shdr(
        ".symtab".into(),
        ShdrField::Offset,
        1 << 40,
    ));
    assert_eq!(past, vec![DiagCode::Oob]);
    let size = codes(Malformed::Shdr(
        ".symtab".into(),
        ShdrField::Size,
        u64::MAX - 7,
    ));
    assert!(size.contains(&DiagCode::Overflow), "{size:?}");
}
