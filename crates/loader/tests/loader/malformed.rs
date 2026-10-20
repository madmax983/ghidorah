//! AC-054 and AC-192: malformed variants, zero-advance tables and the escape values.

use ghidorah_base::DiagCode;
use ghidorah_loader::{LoadError, SymTable};
use ghidorah_testkit::elf::consts::{
    DT_RELAENT, DT_RELENT, DT_RELRENT, DT_SYMENT, R_X86_64_RELATIVE,
};
use ghidorah_testkit::elf::{
    ElfBuilder, HashStyle, ImportKind, Loc, Malformed, Reloc, RelocTable, Section, Symbol,
    malformed_variants,
};

use crate::support::{codes_of, fixture, load_ok, try_load};

#[test]
fn ac_054_elf_malformed_variants() {
    let variants = malformed_variants();
    assert!(variants.len() >= 16, "{} variants", variants.len());
    let mut problems = Vec::new();
    for v in &variants {
        let result = std::panic::catch_unwind(|| codes_of(&v.bytes));
        let Ok(codes) = result else {
            problems.push(format!("{}: panic", v.name));
            continue;
        };
        let want = DiagCode::from_name(v.expect).expect("catalog code");
        if !codes.contains(&want) {
            problems.push(format!("{}: want {}, got {codes:?}", v.name, v.expect));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn fatal_variants_give_format_malformed() {
    for v in malformed_variants() {
        let fatal = matches!(v.name, "empty_file" | "truncated_ehdr" | "bad_magic");
        match try_load(&v.bytes) {
            Err(LoadError::Malformed(d)) => {
                assert!(fatal, "{}: fatal {d}", v.name);
                assert_eq!(
                    LoadError::Malformed(d).code(),
                    ghidorah_base::ErrorCode::FormatMalformed
                );
            }
            Err(other) => panic!("{}: {other}", v.name),
            Ok(_) => assert!(!fatal, "{}: loads", v.name),
        }
    }
}

/// A small PIE with dynamic symbols, RELA, REL and RELR tables and no section headers.
fn dyn_base() -> ElfBuilder {
    ElfBuilder::dyn_object()
        .section(Section::code(
            ".text",
            &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3],
        ))
        .section(Section::data(".data", &[0u8; 32]))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 6))
        .export(Symbol::func("f", Loc::section(".text", 0), 6))
        .import("puts", ImportKind::Plt)
        .import("free", ImportKind::Got)
        .needed("libc.so.6")
        .reloc(Reloc {
            table: RelocTable::Rela,
            at: Loc::section(".data", 0),
            kind: R_X86_64_RELATIVE,
            sym: None,
            addend: 0x10,
        })
        .reloc(Reloc {
            table: RelocTable::Rel,
            at: Loc::section(".data", 8),
            kind: R_X86_64_RELATIVE,
            sym: None,
            addend: 0,
        })
        .relr(Loc::section(".data", 16))
        .hash(HashStyle::Both)
        .strip_section_headers()
}

/// The zero-advance fixtures: one per table kind whose step comes from the file.
fn zero_advance_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let knob = |m: Malformed| dyn_base().malformed(m).build();
    let open_chain = malformed_variants()
        .into_iter()
        .find(|v| v.name == "gnu_hash_open_chain")
        .expect("catalog variant")
        .bytes;
    vec![
        ("dyn_relaent_zero", knob(Malformed::Dynamic(DT_RELAENT, 0))),
        ("dyn_relent_zero", knob(Malformed::Dynamic(DT_RELENT, 0))),
        ("dyn_relrent_zero", knob(Malformed::Dynamic(DT_RELRENT, 0))),
        ("dyn_syment_zero", knob(Malformed::Dynamic(DT_SYMENT, 0))),
        ("gnu_hash_open_chain", open_chain),
        ("verneed_aux_next_zero", verneed_aux_next_zero()),
        ("verneed_next_zero", verneed_next_zero()),
    ]
}

/// The file offset of the `.gnu.version_r` table of `hello.gcc-O2`.
const HELLO_VERNEED: usize = 0x550;

/// `hello.gcc-O2` with `vna_next = 0` in the first of its three version aux entries.
fn verneed_aux_next_zero() -> Vec<u8> {
    let mut bytes = fixture("hello.gcc-O2");
    let cnt = u16::from_le_bytes([bytes[HELLO_VERNEED + 2], bytes[HELLO_VERNEED + 3]]);
    assert_eq!(cnt, 3, "vn_cnt of libc.so.6");
    let aux = HELLO_VERNEED + 16;
    assert_eq!(&bytes[aux + 12..aux + 16], &16u32.to_le_bytes(), "vna_next");
    bytes[aux + 12..aux + 16].copy_from_slice(&0u32.to_le_bytes());
    bytes
}

/// `hello.gcc-O2` with `DT_VERNEEDNUM = 2`, so the walk needs a second entry after `vn_next = 0`.
fn verneed_next_zero() -> Vec<u8> {
    let mut bytes = fixture("hello.gcc-O2");
    let dynamic = 0x2dc0;
    let at = (0..27)
        .map(|i| dynamic + i * 16)
        .find(|&at| bytes[at..at + 8] == 0x6fff_ffffu64.to_le_bytes())
        .expect("DT_VERNEEDNUM");
    bytes[at + 8..at + 16].copy_from_slice(&2u64.to_le_bytes());
    bytes
}

#[test]
fn ac_192_zero_advance() {
    for (name, bytes) in zero_advance_fixtures() {
        let (binary, _) = try_load(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let codes: Vec<DiagCode> = binary.diagnostics.iter().map(|d| d.code).collect();
        assert!(codes.contains(&DiagCode::Loop), "{name}: {codes:?}");
    }
}

#[test]
fn zero_advance_tables_keep_other_tables() {
    let plain = load_ok(&dyn_base().build()).0;
    assert!(plain.diagnostics.is_empty(), "{:?}", plain.diagnostics);
    let relocs = |b: &ghidorah_loader::Binary| b.relocs.len();
    assert_eq!(
        relocs(&plain),
        5,
        "RELA, REL, RELR and two import relocations"
    );
    let no_rela = load_ok(
        &dyn_base()
            .malformed(Malformed::Dynamic(DT_RELAENT, 0))
            .build(),
    )
    .0;
    assert_eq!(relocs(&no_rela), 2, "the REL and RELR entries stay");
    let no_sym = load_ok(
        &dyn_base()
            .malformed(Malformed::Dynamic(DT_SYMENT, 0))
            .build(),
    )
    .0;
    assert_eq!(no_sym.symbols_of(SymTable::Dynsym).count(), 0);
    assert_eq!(relocs(&no_sym), 5);
    let wrong = load_ok(
        &dyn_base()
            .malformed(Malformed::Dynamic(DT_RELENT, 12))
            .build(),
    )
    .0;
    let codes: Vec<DiagCode> = wrong.diagnostics.iter().map(|d| d.code).collect();
    assert_eq!(
        codes,
        vec![DiagCode::BadEntsize],
        "a wrong size is not a loop"
    );
}

#[test]
fn escape_values_from_section0() {
    let base = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3; 4]))
        .section(Section::data(".data", &[1u8; 8]))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 4))
        .import("puts", ImportKind::Plt)
        .needed("libc.so.6");
    let plain = load_ok(&base.build()).0;
    let escaped = load_ok(&base.malformed(Malformed::EscapeCounts).build()).0;
    assert!(plain.sections.len() > 5);
    assert_eq!(
        escaped.sections.len(),
        plain.sections.len(),
        "e_shnum from sh_size"
    );
    let names = |b: &ghidorah_loader::Binary| -> Vec<Vec<u8>> {
        b.sections
            .iter()
            .map(|s| s.name.as_bytes().to_vec())
            .collect()
    };
    assert_eq!(names(&escaped), names(&plain), "e_shstrndx from sh_link");
    assert_eq!(escaped.segments, plain.segments, "e_phnum from sh_info");
    assert_eq!(escaped.symbols, plain.symbols);
    // Section 0 keeps the escape values.
    let s0 = &escaped.sections[0];
    assert_eq!(s0.size, plain.sections.len() as u64);
    assert_eq!(s0.info as usize, plain.segments.len());
    assert!(escaped.diagnostics.is_empty(), "{:?}", escaped.diagnostics);
}

#[test]
fn notes_and_alignment() {
    let id = [0xab, 0xcd, 0xef, 0x01];
    let bytes = ElfBuilder::exec()
        .section(Section::code(".text", &[0xc3]))
        .build_id(&id)
        .x86_features(3)
        .build();
    let (binary, _) = load_ok(&bytes);
    assert_eq!(binary.identity.build_id.as_deref(), Some("abcdef01"));
    let kinds: Vec<u32> = binary.notes.iter().map(|n| n.kind).collect();
    assert_eq!(kinds, vec![3, 5], "build ID, then GNU property");
    assert_eq!(binary.notes[0].name.as_bytes(), b"GNU");
    assert_eq!(binary.notes[0].desc_hex(), "abcdef01");
    assert_eq!(binary.notes[1].desc.len(), 16);
}

#[test]
fn unsupported_reloc_once_per_type() {
    let reloc = |kind| Reloc {
        table: RelocTable::Rela,
        at: Loc::section(".data", 0),
        kind,
        sym: None,
        addend: 0,
    };
    let bytes = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3]))
        .section(Section::data(".data", &[0u8; 8]))
        .reloc(reloc(0x7777))
        .reloc(reloc(0x7777))
        .reloc(reloc(0x8888))
        .build();
    let (binary, _) = load_ok(&bytes);
    let unsupported = binary
        .diagnostics
        .iter()
        .filter(|d| d.code == DiagCode::UnsupportedReloc)
        .count();
    assert_eq!(unsupported, 2, "{:?}", binary.diagnostics);
    assert_eq!(binary.relocs.len(), 3, "the relocations stay in the model");
}

#[test]
fn symbol_name_longer_than_limit_is_cut() {
    let long = "n".repeat(5000);
    let bytes = ElfBuilder::exec()
        .section(Section::code(".text", &[0xc3]))
        .symbol(Symbol::func(&long, Loc::section(".text", 0), 1))
        .build();
    let (binary, _) = load_ok(&bytes);
    let sym = binary
        .symbols_of(SymTable::Symtab)
        .find(|s| s.addr != 0)
        .expect("the symbol");
    assert_eq!(sym.name.len(), 4096);
    assert!(
        binary.diagnostics.iter().any(|d| d.code == DiagCode::Limit),
        "{:?}",
        binary.diagnostics
    );
}

/// A 100-byte ELF64 file with one section header at offset 64. Section 0 is cut after 36
/// bytes, and the low half of its `sh_size` is 0x1234.
fn cut_shdr0() -> Vec<u8> {
    let mut out = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&3u16.to_le_bytes());
    out.extend_from_slice(&62u16.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&64u64.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for v in [64u16, 56, 0, 64, 1, 0xffff] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.resize(96, 0);
    out.extend_from_slice(&[0x34, 0x12, 0x00, 0x00]);
    out
}

#[test]
fn regress_elf_cut_shdr0_no_bogus_shstrndx() {
    let bytes = cut_shdr0();
    assert_eq!(bytes.len(), 100);
    let (b, _) = load_ok(&bytes);
    assert!(
        !b.diagnostics
            .iter()
            .any(|d| d.path == "elf.ehdr.e_shstrndx"),
        "{:?}",
        b.diagnostics
    );
    assert!(
        b.diagnostics.iter().any(|d| d.path == "elf.shdr[0]"),
        "the cut section 0 has its own diagnostic: {:?}",
        b.diagnostics
    );
    assert!(b.sections.is_empty(), "a cut section 0 means no table");
}
