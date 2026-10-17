//! AC-050a and AC-050b: the memory map from `PT_LOAD` segments and unmapped reads.

use std::sync::Arc;

use ghidorah_base::{Limits, Range};
use ghidorah_loader::{MemError, MemoryMap, Perms, Region, RegionSource, SegmentKind};
use ghidorah_testkit::elf::{ElfBuilder, Loc, Section, Symbol};

use crate::support::{fixture, fixture_names, load_ok};

const L: Limits = Limits::DEFAULT;

fn region(first: u64, last: u64, file_off: u64, file_size: u64) -> Region {
    Region {
        name: format!("r{first:x}"),
        va: Range { first, last },
        file_off,
        file_size,
        perms: Perms::READ,
        source: RegionSource::Raw,
    }
}

#[test]
fn ac_050a_memory_map() {
    // Each PT_LOAD with a memory size gives one region with its file part.
    for name in fixture_names() {
        let (binary, map) = load_ok(&fixture(&name));
        let loads: Vec<_> = binary
            .segments
            .iter()
            .filter(|s| s.kind == SegmentKind::Elf(1) && s.mem_size > 0)
            .collect();
        assert_eq!(map.len(), loads.len(), "{name}: one region per PT_LOAD");
        for (seg, reg) in loads.iter().zip(map.regions()) {
            assert_eq!(Some(reg.va), seg.va, "{name}");
            assert_eq!(reg.file_off, seg.file_off, "{name}");
            assert_eq!(reg.file_size, seg.file_size, "{name}");
            assert_eq!(reg.perms, seg.perms, "{name}");
            assert_eq!(reg.source, RegionSource::ElfSegment(seg.index), "{name}");
        }
    }
    // hello: LOAD 0x2db0 0x3db0 filesz 0x260 memsz 0x268. The last 8 bytes are `.bss`.
    let bytes = fixture("hello.gcc-O2");
    let (_, map) = load_ok(&bytes);
    let data = map.read(0x3db0, 16, &L).expect("init and fini arrays");
    assert_eq!(&data[..], &bytes[0x2db0..0x2dc0]);
    assert!(matches!(data, std::borrow::Cow::Borrowed(_)), "no copy");
    assert_eq!(map.va_to_file(0x3db0), Some(0x2db0));
    let tail = map.read(0x400c, 12, &L).expect("data end and bss");
    assert_eq!(&tail[..4], &bytes[0x300c..0x3010]);
    assert_eq!(
        &tail[4..],
        &[0u8; 8],
        "bytes in [filesz, memsz) read as zero"
    );
    assert_eq!(
        map.va_to_file(0x4010),
        None,
        "the zero tail has no file offset"
    );
    let text = map.region_at(0x1090).expect("code region");
    assert_eq!(text.perms, Perms::READ.union(Perms::EXECUTE));
    assert_eq!(text.name, "seg:3");
}

#[test]
fn ac_050a_builder_bss() {
    let code = [0xc3u8; 4];
    let bytes = ElfBuilder::exec()
        .section(Section::code(".text", &code))
        .section(Section::data(".data", &[0xaa; 8]))
        .section(Section::bss(".bss", 0x2000))
        .symbol(Symbol::func("f", Loc::section(".text", 0), 4))
        .build();
    let (binary, map) = load_ok(&bytes);
    let data = binary
        .sections
        .iter()
        .find(|s| s.name.as_bytes() == b".data")
        .expect(".data");
    let bss = binary
        .sections
        .iter()
        .find(|s| s.name.as_bytes() == b".bss")
        .expect(".bss");
    let got = map.read(data.addr, 8, &L).expect(".data");
    assert_eq!(&got[..], &[0xaa; 8]);
    let zeros = map.read(bss.addr, 0x2000, &L).expect(".bss");
    assert_eq!(zeros.len(), 0x2000);
    assert!(zeros.iter().all(|b| *b == 0));
}

#[test]
fn ac_050b_unmapped_nearest() {
    let (_, map) = load_ok(&fixture("hello.gcc-O2"));
    // LOAD 0 is [0x0, 0x67f] and LOAD 1 starts at 0x1000.
    assert_eq!(
        map.read(0x800, 4, &L),
        Err(MemError::Unmapped {
            va: 0x800,
            nearest: Some(0x67f)
        })
    );
    assert_eq!(
        map.read(0xf00, 4, &L),
        Err(MemError::Unmapped {
            va: 0xf00,
            nearest: Some(0x1000)
        })
    );
    // A read that starts in a region and runs into a hole fails at the hole.
    assert_eq!(
        map.read(0x67c, 8, &L),
        Err(MemError::Unmapped {
            va: 0x680,
            nearest: Some(0x67f)
        })
    );
    // Past the last region.
    assert_eq!(
        map.read(0x10_0000, 1, &L),
        Err(MemError::Unmapped {
            va: 0x10_0000,
            nearest: Some(0x4017)
        })
    );
    assert_eq!(map.nearest(0x800), Some(0x67f));
    assert_eq!(map.nearest(0x1004), Some(0x1004));
    let empty = MemoryMap::new(Arc::from(&b""[..]));
    assert_eq!(
        empty.read(0, 1, &L),
        Err(MemError::Unmapped {
            va: 0,
            nearest: None
        })
    );
}

#[test]
fn memmap_read_edges() {
    let file: Arc<[u8]> = Arc::from((0u8..32).collect::<Vec<u8>>());
    let mut map = MemoryMap::new(file);
    assert!(map.map(region(0x100, 0x10f, 0, 16)).is_empty());
    assert!(map.map(region(0x110, 0x11f, 16, 8)).is_empty());
    // Adjacent regions read as one run, with the zero tail of the second region.
    let both = map.read(0x10e, 12, &L).expect("adjacent read");
    assert_eq!(&both[..], &[14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 0, 0]);
    assert!(matches!(both, std::borrow::Cow::Owned(_)));
    assert_eq!(map.read(0x100, 0, &L).map(|b| b.len()), Ok(0));
    assert_eq!(
        map.read(u64::MAX, 2, &L),
        Err(MemError::Overflow {
            va: u64::MAX,
            len: 2
        })
    );
    assert_eq!(
        map.read(0x100, L.file_size + 1, &L),
        Err(MemError::TooLong {
            len: L.file_size + 1,
            max: L.file_size
        })
    );
    assert_eq!(map.va_to_file(0x117), Some(23));
    assert_eq!(map.va_to_file(0x118), None);
    assert_eq!(map.va_to_file(0x200), None);
}

#[test]
fn memmap_later_region_replaces_overlap() {
    let file: Arc<[u8]> = Arc::from((0u8..64).collect::<Vec<u8>>());
    let mut map = MemoryMap::new(file);
    map.map(region(0x100, 0x13f, 0, 64));
    let replaced = map.map(region(0x110, 0x11f, 48, 16));
    assert_eq!(
        replaced,
        vec![Range {
            first: 0x110,
            last: 0x11f
        }]
    );
    let vas: Vec<(u64, u64, u64, u64)> = map
        .regions()
        .map(|r| (r.va.first, r.va.last, r.file_off, r.file_size))
        .collect();
    assert_eq!(
        vas,
        vec![
            (0x100, 0x10f, 0, 16),
            (0x110, 0x11f, 48, 16),
            (0x120, 0x13f, 32, 32),
        ]
    );
    let got = map.read(0x10f, 3, &L).expect("read across the split");
    assert_eq!(&got[..], &[15, 48, 49]);
    assert_eq!(map.read(0x120, 1, &L).expect("right part")[0], 32);
}

#[test]
fn memmap_cuts_file_size() {
    let file: Arc<[u8]> = Arc::from(vec![7u8; 10]);
    let mut map = MemoryMap::new(file);
    // The file part is larger than the region and than the file.
    map.map(region(0x0, 0x3, 8, 100));
    let r = map.region_at(0).expect("region");
    assert_eq!(r.file_size, 2, "cut to the file bytes after the offset");
    assert_eq!(&map.read(0, 4, &L).expect("read")[..], &[7, 7, 0, 0]);
    // A file offset past the end gives no file bytes.
    map.map(region(0x10, 0x13, 99, 4));
    assert_eq!(map.region_at(0x10).map(|r| r.file_size), Some(0));
    assert_eq!(&map.read(0x10, 4, &L).expect("zeros")[..], &[0, 0, 0, 0]);
}

#[test]
fn memmap_map_all_sweeps_in_list_order() {
    let file: Arc<[u8]> = Arc::from((0u8..64).collect::<Vec<u8>>());
    let mut map = MemoryMap::new(file);
    let over = map.map_all(vec![
        region(0x100, 0x13f, 0, 64),
        region(0x200, 0x20f, 0, 16),
        region(0x110, 0x11f, 48, 16),
        region(0x130, 0x14f, 0, 32),
    ]);
    assert_eq!(over, vec![2, 3], "regions 2 and 3 cover parts of region 0");
    let vas: Vec<(u64, u64, u64, u64)> = map
        .regions()
        .map(|r| (r.va.first, r.va.last, r.file_off, r.file_size))
        .collect();
    assert_eq!(
        vas,
        vec![
            (0x100, 0x10f, 0, 16),
            (0x110, 0x11f, 48, 16),
            (0x120, 0x12f, 32, 16),
            (0x130, 0x14f, 0, 32),
            (0x200, 0x20f, 0, 16),
        ]
    );
    // A region that ends at u64::MAX maps without overflow.
    let mut top = MemoryMap::new(Arc::from(vec![1u8; 8]));
    assert!(
        top.map_all(vec![region(u64::MAX - 7, u64::MAX, 0, 8)])
            .is_empty()
    );
    assert_eq!(top.read(u64::MAX - 7, 8, &L).map(|b| b.len()), Ok(8));
    // Many equal regions: the last one wins, and the map holds one region.
    let mut same = MemoryMap::new(Arc::from(vec![0u8; 16]));
    let list: Vec<Region> = (0..5000).map(|i| region(0, 0xf, i % 16, 1)).collect();
    let over = same.map_all(list);
    assert_eq!(over.len(), 4999);
    assert_eq!(same.len(), 1);
    assert_eq!(same.region_at(0).map(|r| r.file_off), Some(4999 % 16));
}

#[test]
fn memmap_map_all_marks_a_region_that_starts_first() {
    // Region 1 starts below region 0, so it is live when region 0 starts.
    let mut map = MemoryMap::new(Arc::from(vec![0u8; 0x200]));
    let over = map.map_all(vec![
        region(0x100, 0x1ff, 0, 0x100),
        region(0x50, 0x150, 0, 0x101),
    ]);
    assert_eq!(over, vec![1], "region 1 covers a part of region 0");
    let vas: Vec<(u64, u64)> = map.regions().map(|r| (r.va.first, r.va.last)).collect();
    assert_eq!(vas, vec![(0x50, 0x150), (0x151, 0x1ff)]);
    assert_eq!(map.region_at(0x151).map(|r| r.file_off), Some(0x51));
    assert_eq!(map.file().len(), 0x200);
    assert_eq!(map.file_arc().len(), 0x200);
    // Old regions of the map come first, so a new region wins over them.
    let mut old = MemoryMap::new(Arc::from(vec![0u8; 0x200]));
    old.map(region(0x0, 0xff, 0, 0x100));
    assert_eq!(old.map_all(vec![region(0x80, 0x17f, 0x80, 0x100)]), vec![0]);
    assert_eq!(old.len(), 2);
}

#[test]
fn perms_bits_and_text() {
    assert_eq!(Perms::from_elf(4).to_string(), "r--");
    assert_eq!(Perms::from_elf(5).to_string(), "r-x");
    assert_eq!(Perms::from_elf(6).to_string(), "rw-");
    assert_eq!(Perms::from_elf(7), Perms::RWX);
    assert_eq!(Perms::from_elf(0xf0), Perms::NONE);
    assert_eq!(Perms::RWX.bits(), 7);
    assert!(Perms::RWX.contains(Perms::WRITE));
    assert!(!Perms::READ.contains(Perms::WRITE));
    assert_eq!(Perms::from_bits(0x10), Perms::ARTIFICIAL);
    assert_eq!(Perms::VOLATILE.bits(), 8);
}

#[test]
fn mem_error_text() {
    let unmapped = MemError::Unmapped {
        va: 0x10,
        nearest: Some(0x20),
    };
    assert!(unmapped.to_string().contains("0x20"));
    let none = MemError::Unmapped {
        va: 0x10,
        nearest: None,
    };
    assert!(none.to_string().contains("no region"));
    assert!(
        MemError::Overflow { va: 1, len: 2 }
            .to_string()
            .contains("last address")
    );
    assert!(
        MemError::TooLong { len: 9, max: 8 }
            .to_string()
            .contains("limit")
    );
}
