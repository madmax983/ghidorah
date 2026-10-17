//! Tests of hex, `Limits`, `bounded_vec`, `Fuel` and the clocks.

use ghidorah_base::hex::{self, HexError};
use ghidorah_base::{
    Bound, Clamp, Clock, FixedClock, Fuel, Limits, ManualClock, OutOfFuel, bounded_count,
    bounded_vec,
};

#[test]
fn hex_table() {
    assert_eq!(hex::encode(&[]), "");
    assert_eq!(hex::encode(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
    let mut out = String::from("x=");
    hex::encode_into(&[0xde, 0xad], &mut out);
    assert_eq!(out, "x=dead");
    assert_eq!(hex::decode("000fABff"), Ok(vec![0x00, 0x0f, 0xab, 0xff]));
    assert_eq!(hex::decode(""), Ok(vec![]));
    assert_eq!(hex::decode("abc"), Err(HexError::OddLength { len: 3 }));
    assert_eq!(hex::decode("0g"), Err(HexError::BadDigit { offset: 1 }));
    assert_eq!(hex::decode("\u{e9}"), Err(HexError::BadDigit { offset: 0 }));
    assert_eq!(
        hex::decode("0\u{e9}0"),
        Err(HexError::BadDigit { offset: 1 })
    );
    assert!(HexError::OddLength { len: 3 }.to_string().contains('3'));
    assert!(HexError::BadDigit { offset: 1 }.to_string().contains('1'));

    assert_eq!(hex::u64_text(0), "0x0");
    assert_eq!(hex::u64_text(0x40_1000), "0x401000");
    assert_eq!(hex::u64_text(u64::MAX), "0xffffffffffffffff");
    assert_eq!(hex::parse_u64("0x0"), Some(0));
    assert_eq!(hex::parse_u64("0xAbC"), Some(0xabc));
    assert_eq!(hex::parse_u64("0x000000000000000f"), Some(15));
    for bad in [
        "",
        "0x",
        "x1",
        "0X1",
        "0x0000000000000000f",
        "0x+1",
        "0x-1",
        "0x 1",
        "1",
    ] {
        assert_eq!(hex::parse_u64(bad), None, "{bad:?}");
    }
    assert_eq!(hex::parse_digits("ff"), Some(255));
    assert_eq!(hex::parse_digits(""), None);
    assert_eq!(hex::parse_digits("0x1"), None);
    assert_eq!(hex::parse_digits("10000000000000000"), None);
}

#[test]
fn limits_defaults() {
    let l = Limits::DEFAULT;
    assert_eq!(l.file_size, 1 << 30);
    assert_eq!(l.program_headers, 65_535);
    assert_eq!(l.sections, 65_535);
    assert_eq!(l.symbols, 4_194_304);
    assert_eq!(l.relocations, 16_777_216);
    assert_eq!(l.notes_per_segment, 4_096);
    assert_eq!(l.string_len, 4_096);
    assert_eq!(l.fdes, 1_048_576);
    assert_eq!(l.cfa_insns_per_fde, 4_096);
    assert_eq!(l.plt_scan_bytes, 16 << 20);
    assert_eq!(l.pe_import_dlls, 4_096);
    assert_eq!(l.pe_imports_per_dll, 65_536);
    assert_eq!(l.pe_exports, 65_536);
    assert_eq!(l.pe_tls_callbacks, 256);
    assert_eq!(l.pe_pdata_entries, 1_048_576);
    assert_eq!(l.pe_unwind_depth, 32);
    assert_eq!(l.pe_debug_entries, 64);
    assert_eq!(Limits::default(), l);
}

#[test]
fn bounded_count_table() {
    let cases = [
        // count, entry size, bytes left, limit -> count, clamp
        (10, 8, 80, 100, 10, None),
        (10, 8, 79, 100, 9, Some(Clamp::Bytes)),
        (10, 8, 80, 5, 5, Some(Clamp::Limit)),
        (10, 8, 16, 5, 2, Some(Clamp::Bytes)),
        (u64::MAX, 24, 240, u64::MAX, 10, Some(Clamp::Bytes)),
        (u64::MAX, 0, 0, 7, 7, Some(Clamp::Limit)),
        (3, 0, 0, 7, 3, None),
        (0, 8, 0, 0, 0, None),
        (1, 8, 0, 10, 0, Some(Clamp::Bytes)),
    ];
    for (count, size, left, limit, want, clamp) in cases {
        let bound = bounded_count(count, size, left, limit);
        assert_eq!(
            bound,
            Bound {
                requested: count,
                count: want,
                clamp,
            },
            "{count} {size} {left} {limit}"
        );
    }
    let (v, bound): (Vec<u64>, Bound) = bounded_vec(u64::MAX, 8, 64, 1 << 20);
    assert_eq!(bound.count, 8);
    assert!(v.capacity() >= 8 && v.capacity() < 1024, "{}", v.capacity());
    assert!(v.is_empty());
}

#[test]
fn fuel_take_and_tick() {
    let mut fuel = Fuel::new(10);
    assert_eq!(fuel.limit(), 10);
    assert_eq!(fuel.take(4), Ok(()));
    assert_eq!(fuel.tick(), Ok(()));
    assert_eq!((fuel.used(), fuel.remaining()), (5, 5));
    assert!(!fuel.is_empty());
    assert_eq!(fuel.take(5), Ok(()));
    assert!(fuel.is_empty());
    assert_eq!(
        fuel.tick(),
        Err(OutOfFuel {
            limit: 10,
            needed: 1
        })
    );
    let mut fuel = Fuel::new(10);
    assert_eq!(
        fuel.take(11),
        Err(OutOfFuel {
            limit: 10,
            needed: 11
        })
    );
    assert!(fuel.is_empty(), "a failed take empties the tank");
    assert_eq!(fuel.take(0), Ok(()));
    assert_eq!(
        fuel.tick(),
        Err(OutOfFuel {
            limit: 10,
            needed: 1
        })
    );
    let mut big = Fuel::unlimited();
    assert_eq!(big.take(u64::MAX - 1), Ok(()));
    assert_eq!(big.tick(), Ok(()));
    assert_eq!(
        big.tick(),
        Err(OutOfFuel {
            limit: u64::MAX,
            needed: 1
        })
    );
    let err = OutOfFuel {
        limit: 3,
        needed: 4,
    };
    assert_eq!(err.code().name(), "BUDGET_EXCEEDED");
    assert!(err.to_string().contains('4'));
}

#[test]
fn clocks() {
    let fixed = FixedClock::new(1_700_000_000_000);
    assert_eq!(fixed.unix_ms(), 1_700_000_000_000);
    assert_eq!(fixed.monotonic_ms(), 0);
    let manual = ManualClock::new(5);
    manual.advance(10);
    assert_eq!((manual.unix_ms(), manual.monotonic_ms()), (15, 10));
    manual.advance(u64::MAX);
    assert_eq!(
        (manual.unix_ms(), manual.monotonic_ms()),
        (u64::MAX, u64::MAX)
    );
    let dynamic: &dyn Clock = &fixed;
    assert_eq!(dynamic.unix_ms(), 1_700_000_000_000);
    assert_eq!(ManualClock::default().unix_ms(), 0);
}
