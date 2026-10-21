//! The raw loader: one region with read, write and execute access at `base`.

use ghidorah_base::{DiagCode, Limits, Range};
use ghidorah_loader::{
    Arch, EntryKind, Format, Kind, LoadError, LoadOpts, Perms, RegionSource, SegmentKind, load,
};

use crate::support::fixture;

#[test]
fn raw_blob_maps_at_base() {
    let code = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
    let opts = LoadOpts::raw(0x1000, Some(0x1002));
    let (binary, map) = load(&code, &opts, &Limits::DEFAULT).expect("raw load");
    assert_eq!(binary.format, Format::Raw);
    assert_eq!(binary.kind, Kind::Raw);
    assert_eq!(binary.arch, Arch::X86_64);
    assert_eq!(binary.bits, 64);
    assert_eq!(binary.image_base, 0x1000);
    assert_eq!(binary.entry_points.len(), 1);
    assert_eq!(binary.entry_points[0].addr, 0x1002);
    assert_eq!(binary.entry_points[0].kind, EntryKind::Entry);
    assert_eq!(binary.segments.len(), 1);
    assert_eq!(binary.segments[0].kind, SegmentKind::Raw);
    assert_eq!(
        binary.segments[0].va,
        Some(Range {
            first: 0x1000,
            last: 0x1005
        })
    );
    let regions: Vec<_> = map.regions().collect();
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].name, "raw");
    assert_eq!(regions[0].perms, Perms::RWX);
    assert_eq!(regions[0].source, RegionSource::Raw);
    assert_eq!(
        &map.read(0x1000, 6, &Limits::DEFAULT).expect("read")[..],
        &code
    );
    assert_eq!(binary.identity.sha256, ghidorah_base::sha256(&code));
}

#[test]
fn raw_ignores_the_magic() {
    let elf = fixture("hello.gcc-O2");
    let (binary, map) = load(&elf, &LoadOpts::raw(0, None), &Limits::DEFAULT).expect("raw");
    assert_eq!(binary.format, Format::Raw);
    assert!(binary.entry_points.is_empty());
    assert!(binary.sections.is_empty());
    assert_eq!(map.len(), 1);
}

#[test]
fn raw_errors() {
    let empty = load(&[], &LoadOpts::raw(0x1000, None), &Limits::DEFAULT);
    assert_eq!(
        empty
            .as_ref()
            .err()
            .and_then(LoadError::diagnostic)
            .map(|d| d.code),
        Some(DiagCode::Oob)
    );
    let wrap = load(
        &[0u8; 16],
        &LoadOpts::raw(u64::MAX - 7, None),
        &Limits::DEFAULT,
    );
    assert_eq!(
        wrap.as_ref()
            .err()
            .and_then(LoadError::diagnostic)
            .map(|d| d.code),
        Some(DiagCode::Overflow)
    );
    let last = load(
        &[0u8; 8],
        &LoadOpts::raw(u64::MAX - 7, None),
        &Limits::DEFAULT,
    );
    assert!(last.is_ok(), "a blob can end at u64::MAX");
}
