//! AC-056a and the probe table: the format names and the unsupported formats.

use ghidorah_base::{ErrorCode, Limits};
use ghidorah_loader::{
    Detected, ElfClass, ElfData, Format, LoadError, LoadOpts, SUPPORTED_FORMATS, load, probe,
};
use ghidorah_testkit::elf::{Class, Endian, header_only};

use crate::support::{fixture, try_load};

const EM_386: u16 = 3;
const EM_PPC64: u16 = 21;
const ET_EXEC: u16 = 2;

#[test]
fn ac_056a_elf32_and_be_unsupported() {
    let cases = [
        (Class::Elf32, Endian::Little, EM_386, "elf32-le"),
        (Class::Elf64, Endian::Big, EM_PPC64, "elf64-be"),
        (Class::Elf32, Endian::Big, EM_PPC64, "elf32-be"),
    ];
    for (class, endian, machine, name) in cases {
        let bytes = header_only(class, endian, ET_EXEC, machine);
        match try_load(&bytes) {
            Err(e @ LoadError::UnsupportedFormat { .. }) => {
                assert_eq!(e.code(), ErrorCode::UnsupportedFormat);
                let LoadError::UnsupportedFormat {
                    detected,
                    supported,
                } = &e
                else {
                    unreachable!()
                };
                assert_eq!(detected, name);
                assert_eq!(*supported, SUPPORTED_FORMATS);
                let text = e.to_string();
                assert!(text.contains(name) && text.contains("elf64-le"), "{text}");
            }
            other => panic!("{name}: {other:?}"),
        }
    }
    assert!(SUPPORTED_FORMATS.contains(&"elf64-le"));
    assert!(SUPPORTED_FORMATS.contains(&"raw"));
    assert_eq!(Format::Elf64Le.name(), "elf64-le");
    assert_eq!(Format::Raw.name(), "raw");
}

/// Writes `value` at `at` in `bytes`, little-endian.
fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
    bytes[at..at + value.len()].copy_from_slice(value);
}

/// A minimal PE header: `MZ`, `e_lfanew = 0x40`, `PE\0\0`, `Machine` and the optional magic.
fn pe(machine: u16, magic: u16) -> Vec<u8> {
    let mut b = vec![0u8; 0x100];
    put(&mut b, 0, b"MZ");
    put(&mut b, 0x3c, &0x40u32.to_le_bytes());
    put(&mut b, 0x40, b"PE\0\0");
    put(&mut b, 0x44, &machine.to_le_bytes());
    put(&mut b, 0x58, &magic.to_le_bytes());
    b
}

#[test]
fn probe_table() {
    let hello = fixture("hello.gcc-O2");
    assert_eq!(
        probe(&hello),
        Detected::Elf {
            class: ElfClass::Elf64,
            data: ElfData::Le,
            e_type: Some(3),
            machine: Some(62)
        }
    );
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (hello, "elf64-le"),
        (
            header_only(Class::Elf64, Endian::Little, 1, 62),
            "elf64-le-rel",
        ),
        (
            header_only(Class::Elf64, Endian::Little, 4, 62),
            "elf64-le-core",
        ),
        (
            header_only(Class::Elf64, Endian::Little, 0x1234, 62),
            "elf64-le-type-0x1234",
        ),
        (pe(0x8664, 0x20b), "pe32+-x86_64"),
        (pe(0x14c, 0x10b), "pe32-i386"),
        (pe(0xaa64, 0x20b), "pe32+-arm64"),
        (pe(0x1c4, 0x10b), "pe32-0x1c4"),
        (pe(0x8664, 0x999), "pe-magic-0x999"),
        (b"MZ".to_vec(), "dos_mz"),
        (vec![b'M', b'Z', 0, 0], "dos_mz"),
        (vec![0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0], "macho32"),
        (vec![0xce, 0xfa, 0xed, 0xfe], "macho32"),
        (vec![0xcf, 0xfa, 0xed, 0xfe], "macho64"),
        (vec![0xfe, 0xed, 0xfa, 0xcf], "macho64"),
        (vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2], "fat"),
        (vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52], "java_class"),
        (vec![0xca, 0xfe, 0xba, 0xbe], "fat"),
        (vec![0x7f, b'E', b'L', b'F', 3, 1], "elf-class3"),
        (vec![0x7f, b'E', b'L', b'F', 2, 9], "elf64-data9"),
        (Vec::new(), "unknown"),
        (vec![0x7f, b'E', b'L'], "unknown"),
        (b"hello world".to_vec(), "unknown"),
    ];
    for (bytes, name) in cases {
        assert_eq!(probe(&bytes).name(), name, "{bytes:02x?}");
    }
    // An `e_lfanew` past the end of the file gives `dos_mz`.
    let mut far = pe(0x8664, 0x20b);
    put(&mut far, 0x3c, &0x1000u32.to_le_bytes());
    assert_eq!(probe(&far), Detected::DosMz);
    // A PE signature with a cut COFF header keeps the PE kind without the fields.
    let cut = pe(0x8664, 0x20b)[..0x45].to_vec();
    assert_eq!(probe(&cut).name(), "pe");
    assert_eq!(
        probe(&cut),
        Detected::Pe {
            magic: None,
            machine: None
        }
    );
}

#[test]
fn unsupported_formats_name_the_probe() {
    for (bytes, name) in [
        (pe(0x8664, 0x20b), "pe32+-x86_64"),
        (b"MZ".to_vec(), "dos_mz"),
        (vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0], "macho64"),
        (vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52], "java_class"),
        (
            header_only(Class::Elf64, Endian::Little, 1, 62),
            "elf64-le-rel",
        ),
    ] {
        match try_load(&bytes) {
            Err(LoadError::UnsupportedFormat { detected, .. }) => assert_eq!(detected, name),
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[test]
fn unknown_and_short_files_are_malformed() {
    for (bytes, code) in [
        (Vec::new(), "E_OOB"),
        (vec![0x7f, b'E'], "E_OOB"),
        (vec![0x7f, b'E', b'L', b'F'], "E_OOB"),
        (vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0], "E_OOB"),
        (b"hello world".to_vec(), "E_BAD_MAGIC"),
        (vec![0x7f, b'E', b'L', b'F', 3, 1, 1], "E_BAD_MAGIC"),
    ] {
        match try_load(&bytes) {
            Err(LoadError::Malformed(d)) => assert_eq!(d.code.name(), code, "{bytes:?}"),
            other => panic!("{bytes:?}: {other:?}"),
        }
    }
}

#[test]
fn file_size_limit() {
    let limits = Limits {
        file_size: 16,
        ..Limits::DEFAULT
    };
    let e = load(&[0u8; 17], &LoadOpts::AUTO, &limits).expect_err("too large");
    assert_eq!(
        e,
        LoadError::TooLarge {
            size: 17,
            limit: 16
        }
    );
    assert_eq!(e.code(), ErrorCode::LimitExceeded);
    assert!(e.to_string().contains("17 bytes"));
    assert!(e.diagnostic().is_none());
}

#[test]
fn diagnostic_and_error_text() {
    use ghidorah_base::DiagCode;
    use ghidorah_loader::Diagnostic;
    let full = Diagnostic::new(DiagCode::Oob, "elf.phdr")
        .at(0x40)
        .need(0x2d8)
        .have(0x10)
        .hint("cut table");
    assert_eq!(
        full.to_string(),
        "E_OOB at elf.phdr, offset 0x40, need 0x2d8, have 0x10: cut table"
    );
    assert_eq!(
        Diagnostic::new(DiagCode::Loop, "x").to_string(),
        "E_LOOP at x"
    );
    let e = LoadError::Malformed(full.clone());
    assert_eq!(e.diagnostic(), Some(&full));
    assert!(e.to_string().starts_with("The file is malformed: E_OOB"));
    let u = LoadError::UnsupportedFormat {
        detected: "macho64".to_string(),
        supported: SUPPORTED_FORMATS,
    };
    assert_eq!(u.diagnostic(), None);
    assert_eq!(u.code(), ErrorCode::UnsupportedFormat);
}

#[test]
fn diagnostics_above_the_cap_are_counted() {
    use ghidorah_loader::diag::MAX_DIAGNOSTICS;
    use ghidorah_testkit::elf::{ElfBuilder, Loc, Reloc, RelocTable, Section};
    // Each relocation type gives one diagnostic, so 1,100 types pass the cap.
    let mut b = ElfBuilder::dyn_object()
        .section(Section::code(".text", &[0xc3]))
        .section(Section::data(".data", &[0u8; 8]));
    for kind in 0..1100u32 {
        b = b.reloc(Reloc {
            table: RelocTable::Rela,
            at: Loc::section(".data", 0),
            kind: 0x1000 + kind,
            sym: None,
            addend: 0,
        });
    }
    let (binary, _) = crate::support::load_ok(&b.build());
    assert_eq!(binary.diagnostics.len(), MAX_DIAGNOSTICS);
    let kept = u64::try_from(MAX_DIAGNOSTICS).expect("cap");
    assert_eq!(binary.diagnostics_dropped, 1100 - kept);
}
