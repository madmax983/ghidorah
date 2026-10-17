//! The `DW_EH_PE` pointer encoding table.

use std::sync::Arc;

use ghidorah_base::Range;
use ghidorah_kernel::{Endian, Reader};
use ghidorah_loader::ehframe::{Bases, PointerError, read_pointer};
use ghidorah_loader::{MemoryMap, Perms, Region, RegionSource};

/// The base of the reader buffer in the table.
const START: u64 = 0x1000;
/// The data base in the table.
const DATA: u64 = 0x8000;

/// One row: encoding, bytes, reader position, expected value and expected length.
type Case = (
    u8,
    &'static [u8],
    usize,
    Result<Option<u64>, PointerError>,
    usize,
);

#[test]
fn dw_eh_pe_encoding_table() {
    let cases: &[Case] = &[
        // Formats with an absolute base.
        (
            0x00,
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            0,
            Ok(Some(0x1122_3344_5566_7788)),
            8,
        ),
        (0x01, &[0xe5, 0x8e, 0x26], 0, Ok(Some(624_485)), 3),
        (0x02, &[0x34, 0x12], 0, Ok(Some(0x1234)), 2),
        (0x03, &[0x78, 0x56, 0x34, 0x12], 0, Ok(Some(0x1234_5678)), 4),
        (
            0x04,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            0,
            Ok(Some(0x0807_0605_0403_0201)),
            8,
        ),
        (
            0x08,
            &[0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            0,
            Ok(Some(u64::MAX - 7)),
            8,
        ),
        (0x09, &[0x7f], 0, Ok(Some(u64::MAX)), 1),
        (0x0a, &[0xfe, 0xff], 0, Ok(Some(u64::MAX - 1)), 2),
        (
            0x0b,
            &[0x00, 0x00, 0x00, 0x80],
            0,
            Ok(Some(0xffff_ffff_8000_0000)),
            4,
        ),
        (0x0c, &[0xff; 8], 0, Ok(Some(u64::MAX)), 8),
        // pcrel adds the address of the field.
        (
            0x1b,
            &[0xf0, 0xff, 0xff, 0xff],
            0,
            Ok(Some(START - 0x10)),
            4,
        ),
        (
            0x1b,
            &[0, 0, 0, 0, 0x10, 0, 0, 0],
            4,
            Ok(Some(START + 4 + 0x10)),
            4,
        ),
        (0x13, &[0x20, 0, 0, 0], 0, Ok(Some(START + 0x20)), 4),
        (
            0x10,
            &[0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            0,
            Ok(Some(START - 8)),
            8,
        ),
        (0x19, &[0x70], 0, Ok(Some(START - 0x10)), 1),
        (0x11, &[0x10], 0, Ok(Some(START + 0x10)), 1),
        // datarel adds the data base.
        (0x3b, &[0x04, 0, 0, 0], 0, Ok(Some(DATA + 4)), 4),
        (0x3a, &[0xfc, 0xff], 0, Ok(Some(DATA - 4)), 2),
        // omit reads nothing.
        (0xff, &[1, 2, 3, 4], 0, Ok(None), 0),
        // Unsupported bases and formats.
        (0x23, &[0, 0, 0, 0], 0, Err(PointerError::Encoding(0x23)), 0),
        (0x43, &[0, 0, 0, 0], 0, Err(PointerError::Encoding(0x43)), 0),
        (0x50, &[0; 8], 0, Err(PointerError::Encoding(0x50)), 0),
        (0x0d, &[0; 8], 0, Err(PointerError::Encoding(0x0d)), 0),
        (0x05, &[0; 8], 0, Err(PointerError::Encoding(0x05)), 0),
        // Bad values keep the position.
        (0x03, &[1, 2, 3], 0, Err(PointerError::Eof), 0),
        (0x0c, &[1, 2, 3, 4, 5, 6, 7], 0, Err(PointerError::Eof), 0),
        (0x01, &[0x80, 0x80], 0, Err(PointerError::Eof), 0),
        (
            0x01,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02],
            0,
            Err(PointerError::BadLeb),
            0,
        ),
        // The address passes the 64-bit range.
        (
            0x13,
            &[0xff, 0xff, 0xff, 0xff],
            0,
            Ok(Some(START + 0xffff_ffff)),
            4,
        ),
        (
            0x9b,
            &[0, 0, 0, 0],
            0,
            Err(PointerError::Unmapped(START)),
            4,
        ),
    ];
    for (i, (enc, bytes, pos, want, len)) in cases.iter().enumerate() {
        let mut r = Reader::new(bytes, Endian::Little);
        r.seek(*pos).expect("seek");
        let bases = Bases {
            start: START,
            data: DATA,
        };
        let got = read_pointer(&mut r, *enc, bases, None);
        assert_eq!(&got, want, "row {i}: encoding {enc:#04x}");
        let used = r.pos() - pos;
        let want_len = if got.is_ok() || matches!(got, Err(PointerError::Unmapped(_))) {
            *len
        } else {
            0
        };
        assert_eq!(used, want_len, "row {i}: encoding {enc:#04x}: bytes read");
    }
}

#[test]
fn pointer_overflow() {
    let bases = Bases {
        start: u64::MAX - 1,
        data: u64::MAX,
    };
    for (enc, bytes) in [
        (0x1b_u8, &[0x10u8, 0, 0, 0][..]),
        (0x13, &[0x10, 0, 0, 0]),
        (0x3b, &[0x01, 0, 0, 0]),
    ] {
        let mut r = Reader::new(bytes, Endian::Little);
        assert_eq!(
            read_pointer(&mut r, enc, bases, None),
            Err(PointerError::Overflow),
            "{enc:#04x}"
        );
    }
    let low = Bases { start: 0, data: 0 };
    let mut r = Reader::new(&[0xf0, 0xff, 0xff, 0xff], Endian::Little);
    assert_eq!(
        read_pointer(&mut r, 0x1b, low, None),
        Err(PointerError::Overflow)
    );
}

#[test]
fn indirect_pointer_reads_memory() {
    // The file holds 8 bytes of pointer table at file offset 0, mapped at 0x5000.
    let file: Arc<[u8]> = Arc::from(&0xdead_beef_u64.to_le_bytes()[..]);
    let mut map = MemoryMap::new(file);
    map.map(Region {
        name: "seg:0".into(),
        va: Range::with_len(0x5000, 0x10).expect("range"),
        file_off: 0,
        file_size: 8,
        perms: Perms::READ,
        source: RegionSource::ElfSegment(0),
    });
    let bases = Bases {
        start: 0x4000,
        data: 0,
    };
    // pcrel | sdata4 | indirect: the field at 0x4000 points to 0x5000.
    let bytes = 0x1000u32.to_le_bytes();
    let mut r = Reader::new(&bytes, Endian::Little);
    assert_eq!(
        read_pointer(&mut r, 0x9b, bases, Some(&map)),
        Ok(Some(0xdead_beef))
    );
    assert_eq!(r.pos(), 4);
    // The zero tail of the region has no file bytes.
    let bytes = 0x1008u32.to_le_bytes();
    let mut r = Reader::new(&bytes, Endian::Little);
    assert_eq!(read_pointer(&mut r, 0x9b, bases, Some(&map)), Ok(Some(0)));
    let bytes = 0x2000u32.to_le_bytes();
    let mut r = Reader::new(&bytes, Endian::Little);
    assert_eq!(
        read_pointer(&mut r, 0x9b, bases, Some(&map)),
        Err(PointerError::Unmapped(0x6000))
    );
}

#[test]
fn pointer_error_text() {
    for e in [
        PointerError::Eof,
        PointerError::BadLeb,
        PointerError::Encoding(0x23),
        PointerError::Overflow,
        PointerError::Unmapped(0x10),
    ] {
        assert!(!e.to_string().is_empty());
        let _ = e.code();
    }
    assert_eq!(PointerError::Eof.code(), ghidorah_base::DiagCode::Oob);
    assert_eq!(
        PointerError::Encoding(1).code(),
        ghidorah_base::DiagCode::BadMagic
    );
    assert_eq!(
        PointerError::Overflow.code(),
        ghidorah_base::DiagCode::Overflow
    );
}
