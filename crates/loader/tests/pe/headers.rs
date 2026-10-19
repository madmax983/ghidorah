//! AC-244 and AC-254: the PE headers, the data directories and the section table, and the PE
//! forms that do not load.

use ghidorah_loader::{
    Detected, EntryKind, Format, Kind, LoadError, SUPPORTED_FORMATS, SectionKind, probe,
};
use ghidorah_testkit::pe;

use crate::support::{IMAGES, fixture, load_fixture, load_variant, readobj, text, try_load};

/// The data directory names of `llvm-readobj` in index order.
const DIRS: [&str; 16] = [
    "ExportTable",
    "ImportTable",
    "ResourceTable",
    "ExceptionTable",
    "CertificateTable",
    "BaseRelocationTable",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLSTable",
    "LoadConfigTable",
    "BoundImport",
    "IAT",
    "DelayImportDescriptor",
    "CLRRuntimeHeader",
    "Reserved",
];

/// Gives the little-endian `u32` at `at`.
fn le32(bytes: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes(
        bytes[at..at + 4].try_into().expect("4 bytes"),
    ))
}

#[test]
fn ac_244_pe_headers_golden() {
    for name in IMAGES {
        let bytes = fixture(name);
        let (b, _) = load_fixture(name);
        let gold = readobj(name);
        assert_eq!(b.format, Format::Pe32Plus, "{name}");
        let dos = gold.child("DOSHeader").expect("DOSHeader");
        assert_eq!(dos.get("Magic"), Some("MZ"));
        assert_eq!(
            le32(&bytes, 0x3c),
            dos.num("AddressOfNewExeHeader"),
            "{name}"
        );
        let coff = gold.child("ImageFileHeader").expect("ImageFileHeader");
        let opt = gold
            .child("ImageOptionalHeader")
            .expect("ImageOptionalHeader");
        let h = b.pe.expect("the PE headers");
        assert_eq!(u64::from(h.machine), coff.num("Machine"), "{name}");
        assert_eq!(b.sections.len() as u64, coff.num("SectionCount"), "{name}");
        assert_eq!(u64::from(h.characteristics), coff.num("Characteristics"));
        let dll = h.characteristics & 0x2000 != 0;
        assert_eq!(b.kind, if dll { Kind::Dyn } else { Kind::Exec }, "{name}");
        assert_eq!(u64::from(h.magic), opt.num("Magic"), "{name}");
        assert_eq!(b.image_base, opt.num("ImageBase"), "{name}");
        let entry = opt.num("AddressOfEntryPoint");
        let entries: Vec<u64> = b
            .entry_points
            .iter()
            .filter(|e| e.kind == EntryKind::Entry)
            .map(|e| e.addr)
            .collect();
        assert_eq!(entries, vec![b.image_base + entry], "{name}");
        for (field, value) in [
            ("SectionAlignment", h.section_alignment),
            ("FileAlignment", h.file_alignment),
            ("SizeOfImage", h.size_of_image),
            ("SizeOfHeaders", h.size_of_headers),
        ] {
            assert_eq!(u64::from(value), opt.num(field), "{name} {field}");
        }
        assert_eq!(u64::from(h.subsystem), opt.num("Subsystem"), "{name}");
        assert_eq!(
            u64::from(h.dll_characteristics),
            opt.num("Characteristics"),
            "{name}"
        );
        let count = opt.num("NumberOfRvaAndSize").min(16);
        assert_eq!(b.data_dirs.len() as u64, count, "{name}");
        let table = opt.child("DataDirectory").expect("DataDirectory");
        for (d, dir_name) in b.data_dirs.iter().zip(DIRS) {
            assert_eq!(u64::from(d.rva), table.num(&format!("{dir_name}RVA")));
            assert_eq!(u64::from(d.size), table.num(&format!("{dir_name}Size")));
        }
        let sections: Vec<_> = gold
            .child("Sections")
            .expect("Sections")
            .all("Section")
            .collect();
        assert_eq!(sections.len(), b.sections.len(), "{name}");
        for (s, g) in b.sections.iter().zip(sections) {
            let label = g.get("Name").expect("a name");
            let want = label.split(" (").next().unwrap_or(label);
            assert_eq!(text(Some(&s.name)), want, "{name}");
            assert_eq!(u64::from(s.index) + 1, g.num("Number"), "{name} {want}");
            assert_eq!(s.kind, SectionKind::Pe);
            assert_eq!(s.addr, b.image_base + g.num("VirtualAddress"), "{want}");
            assert_eq!(s.size, g.num("VirtualSize"), "{name} {want}");
            assert_eq!(s.entsize, g.num("RawDataSize"), "{name} {want}");
            assert_eq!(s.file_off, g.num("PointerToRawData"), "{name} {want}");
            assert_eq!(s.flags, g.num("Characteristics"), "{name} {want}");
        }
    }
}

#[test]
fn data_dirs_above_16_count_as_16() {
    let (b, map) = load_variant("dirs_32");
    assert_eq!(b.data_dirs.len(), 16);
    assert!(b.data_dirs.iter().zip(0u8..).all(|(d, i)| d.index == i));
    assert!(!map.is_empty(), "the file maps");
    let (few, _) = load_ok_dirs(3);
    assert_eq!(
        few.data_dirs.len(),
        3,
        "a smaller count reads fewer directories"
    );
}

/// Loads the base variant with `NumberOfRvaAndSizes = count`.
fn load_ok_dirs(count: u32) -> (ghidorah_loader::Binary, ghidorah_loader::MemoryMap) {
    let bytes = pe::base().dir_count(count).build();
    crate::support::load_ok(&bytes)
}

#[test]
fn ac_254_pe_unsupported_variants() {
    assert!(SUPPORTED_FORMATS.contains(&"pe32+-x86_64"));
    assert_eq!(SUPPORTED_FORMATS, &["elf64-le", "pe32+-x86_64", "raw"]);
    for (variant, detected) in [
        ("pe32_i386", "pe32-i386"),
        ("pe32plus_arm64", "pe32+-arm64"),
        ("mz_no_pe", "dos_mz"),
    ] {
        let bytes = pe::builder(variant).expect("the variant").build();
        assert_eq!(probe(&bytes).name(), detected);
        match try_load(&bytes) {
            Err(LoadError::UnsupportedFormat {
                detected: d,
                supported,
            }) => {
                assert_eq!(d, detected, "{variant}");
                assert_eq!(supported, SUPPORTED_FORMATS, "{variant}");
            }
            other => panic!("{variant}: {other:?}"),
        }
    }
    let (b, _) = load_variant("minimal");
    assert_eq!(b.format, Format::Pe32Plus);
    assert!(matches!(
        probe(&pe::base().build()),
        Detected::Pe {
            magic: Some(0x20b),
            machine: Some(0x8664)
        }
    ));
}

#[test]
fn cut_pe_headers_are_malformed() {
    let full = pe::base().build();
    for len in [0x46, 0x5a, 0x80, 0xc0] {
        match try_load(&full[..len]) {
            Err(LoadError::Malformed(d)) => assert_eq!(d.code.name(), "E_OOB", "{len:#x}"),
            other => panic!("{len:#x}: {other:?}"),
        }
    }
}
