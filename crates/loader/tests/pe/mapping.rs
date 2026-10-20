//! AC-245: the loader-faithful RVA mapping of design Section 4.10.

use ghidorah_base::DiagCode;
use ghidorah_loader::{Perms, RegionSource, SegmentKind};
use ghidorah_testkit::pe::{self, EXE_BASE};

use crate::support::{codes, load_fixture, load_variant, read, text};

/// Gives the region names of a map in address order.
fn names(map: &ghidorah_loader::MemoryMap) -> Vec<String> {
    map.regions().map(|r| r.name.clone()).collect()
}

#[test]
fn ac_245_rva_mapping_variants() {
    // The headers map at the image base with read access.
    let (b, map) = load_variant("minimal");
    let head = map.region_at(EXE_BASE).expect("the headers region");
    assert_eq!(head.name, "headers");
    assert_eq!(head.perms, Perms::READ);
    assert_eq!(head.source, RegionSource::PeHeaders);
    assert_eq!(read(&map, EXE_BASE, 2), b"MZ");
    assert_eq!(read(&map, EXE_BASE + 0x40, 4), b"PE\0\0");
    let text_region = map.region_at(EXE_BASE + 0x1000).expect(".text");
    assert_eq!(text_region.name, ".text");
    assert_eq!(text_region.perms, Perms::READ.union(Perms::EXECUTE));
    assert_eq!(
        map.region_at(EXE_BASE + 0x2000).map(|r| r.perms),
        Some(Perms::READ.union(Perms::WRITE))
    );
    assert_eq!(
        b.segments.first().map(|s| s.kind),
        Some(SegmentKind::PeHeaders)
    );
    assert!(
        b.segments
            .iter()
            .skip(1)
            .all(|s| s.kind == SegmentKind::PeSection)
    );
    assert!(codes(&b).is_empty(), "{:?}", b.diagnostics);

    // `VirtualSize` 0 means `SizeOfRawData`.
    let (_, map) = load_variant("vsize_zero");
    let zv = map.region_at(EXE_BASE + 0x3000).expect(".zv");
    assert_eq!(zv.va.len(), 0x200);
    assert_eq!(read(&map, EXE_BASE + 0x3000, 0x40), vec![0x22; 0x40]);
    assert_eq!(read(&map, EXE_BASE + 0x3040, 0x10), vec![0; 0x10]);

    // `PointerToRawData` rounds down to a multiple of 0x200.
    let (_, map) = load_variant("raw_ptr_low");
    assert_eq!(
        map.region_at(EXE_BASE + 0x3000).map(|r| r.file_off),
        Some(0)
    );
    assert_eq!(read(&map, EXE_BASE + 0x3000, 2), b"MZ");
    let bytes = pe::builder("raw_ptr_unaligned").expect("variant").build();
    let (_, map) = crate::support::load_ok(&bytes);
    assert_eq!(
        map.region_at(EXE_BASE + 0x3000).map(|r| r.file_off),
        Some(0x400)
    );
    assert_eq!(read(&map, EXE_BASE + 0x3000, 0x10), bytes[0x400..0x410]);

    // RVAs inside the headers read the header bytes, so a table there loads.
    let (b, _) = load_variant("rva_in_headers");
    let names_of: Vec<(String, String)> = b
        .imports
        .iter()
        .map(|i| (text(i.lib.as_ref()), text(i.name.as_ref())))
        .collect();
    assert_eq!(names_of, vec![("k32.dll".to_owned(), "Beep".to_owned())]);

    // A later section replaces the overlapped part of an earlier one.
    let (b, map) = load_variant("overlap");
    assert!(
        codes(&b).contains(&DiagCode::Overlap),
        "{:?}",
        b.diagnostics
    );
    assert_eq!(read(&map, EXE_BASE + 0x1000, 1), [0xaa]);
    assert_eq!(read(&map, EXE_BASE + 0x2000, 1), [0xbb]);
    assert_eq!(names(&map), vec!["headers", ".a", ".b"]);
    let mut last = None;
    for r in map.regions() {
        assert!(
            last.is_none_or(|l| l < r.va.first),
            "the regions are disjoint"
        );
        last = Some(r.va.last);
    }

    // A section past the end of the file keeps its zero-filled part.
    let (b, map) = load_variant("past_eof");
    assert!(codes(&b).contains(&DiagCode::Oob), "{:?}", b.diagnostics);
    let far = map.region_at(EXE_BASE + 0x3000).expect(".far");
    assert_eq!(far.file_size, 0);
    assert_eq!(read(&map, EXE_BASE + 0x3000, 0x10), vec![0; 0x10]);

    // A zero-fill section has no file bytes.
    let (_, map) = load_variant("bss");
    let bss = map.region_at(EXE_BASE + 0x3000).expect(".bss");
    assert_eq!((bss.file_size, bss.va.len()), (0, 0x80));

    // `NumberOfRvaAndSizes` above 16 counts as 16.
    let (b, _) = load_variant("dirs_32");
    assert_eq!(b.data_dirs.len(), 16);
}

#[test]
fn regress_pe_low_alignment_maps_flat() {
    let (b, map) = load_variant("low_alignment");
    assert_eq!(
        read(&map, EXE_BASE + 0x280, 4),
        [0x31, 0xc0, 0xc3, 0x90],
        "the entry reads the bytes at file offset 0x280"
    );
    assert_eq!(
        map.region_at(EXE_BASE + 0x280).map(|r| r.file_off),
        Some(0x280)
    );
    assert!(b.diagnostics.is_empty(), "{:?}", b.diagnostics);
}

#[test]
fn fixture_reads_follow_the_sections() {
    let (b, map) = load_fixture("pe_main.exe");
    for s in &b.sections {
        let Some(va) = s.va else {
            continue;
        };
        let region = map.region_at(va.first).expect("a mapped section");
        assert_eq!(region.name, text(Some(&s.name)));
        assert_eq!(region.file_off, s.file_off & !0x1ff);
        let len = s.entsize.min(s.size).min(0x40);
        let want = &crate::support::fixture("pe_main.exe")
            [usize::try_from(s.file_off).expect("an offset")..]
            [..usize::try_from(len).expect("a length")];
        assert_eq!(read(&map, va.first, len), want, "{}", text(Some(&s.name)));
    }
    assert_eq!(b.segments.len(), b.sections.len() + 1);
}
