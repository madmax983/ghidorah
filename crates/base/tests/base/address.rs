//! Tests of `Address`, `SpaceId` and the default names (design Sections 3.1 and 3.4).

use ghidorah_base::{Address, DefaultKind, DefaultName, SpaceId};

#[test]
fn address_size_and_order() {
    assert_eq!(std::mem::size_of::<Address>(), 16);
    assert_eq!(SpaceId::RAM.code(), 1);
    assert_eq!(SpaceId::EXTERNAL.code(), 10);
    assert_eq!(SpaceId::from_code(1), Some(SpaceId::RAM));
    assert_eq!(SpaceId::from_code(10), Some(SpaceId::EXTERNAL));
    for reserved in [0u8, 2, 3, 9, 11, 255] {
        assert_eq!(SpaceId::from_code(reserved), None, "code {reserved}");
    }
    // The order is (space, off): every RAM address comes before every EXTERNAL address.
    assert!(Address::ram(u64::MAX) < Address::external(0));
    assert!(Address::ram(1) < Address::ram(2));
    assert_eq!(Address::ram(5).space, SpaceId::RAM);
    assert_eq!(Address::external(5).space, SpaceId::EXTERNAL);
    assert!(Address::ram(0).is_ram());
    assert!(!Address::external(0).is_ram());
    assert_eq!(Address::new(SpaceId::RAM, 7), Address::ram(7));
}

#[test]
fn address_text_table() {
    let good = [
        ("0x0", Address::ram(0), "0x0"),
        ("0x401000", Address::ram(0x40_1000), "0x401000"),
        ("0x00401000", Address::ram(0x40_1000), "0x401000"),
        ("0xDEADbeef", Address::ram(0xdead_beef), "0xdeadbeef"),
        (
            "0xffffffffffffffff",
            Address::ram(u64::MAX),
            "0xffffffffffffffff",
        ),
        ("ext:0x3", Address::external(3), "ext:0x3"),
        ("ext:0x0", Address::external(0), "ext:0x0"),
    ];
    for (text, want, shown) in good {
        assert_eq!(Address::parse(text), Ok(want), "{text}");
        assert_eq!(text.parse::<Address>(), Ok(want), "{text}");
        assert_eq!(want.to_string(), shown, "{text}");
    }
    let bad = [
        "",
        "0x",
        "401000",
        "0X401000",
        "0x10000000000000000",
        "0x1g",
        "-0x1",
        "+0x1",
        " 0x1",
        "ext:",
        "ext:3",
        "ext:0x",
        "EXT:0x3",
        "ram:0x3",
    ];
    for text in bad {
        assert!(Address::parse(text).is_err(), "{text:?} must not parse");
    }
}

#[test]
fn default_name_table() {
    let good = [
        ("FUN_00401130", DefaultKind::Fun, Address::ram(0x40_1130)),
        ("LAB_0040113a", DefaultKind::Lab, Address::ram(0x40_113a)),
        ("DAT_00404010", DefaultKind::Dat, Address::ram(0x40_4010)),
        ("EXT_00000003", DefaultKind::Ext, Address::external(3)),
        ("FUN_1", DefaultKind::Fun, Address::ram(1)),
        ("FUN_ABCDEF", DefaultKind::Fun, Address::ram(0xab_cdef)),
        (
            "FUN_ffffffffffffffff",
            DefaultKind::Fun,
            Address::ram(u64::MAX),
        ),
    ];
    for (text, kind, addr) in good {
        assert_eq!(DefaultName::parse(text), Some(DefaultName { kind, addr }), "{text}");
    }
    assert_eq!(DefaultName::new(DefaultKind::Fun, 0x40_1130).to_string(), "FUN_00401130");
    assert_eq!(DefaultName::new(DefaultKind::Ext, 3).to_string(), "EXT_00000003");
    assert_eq!(DefaultName::new(DefaultKind::Ext, 3).addr, Address::external(3));
    assert_eq!(
        DefaultName::new(DefaultKind::Dat, 0x1_4000_1000).to_string(),
        "DAT_140001000"
    );
    let prefixes: Vec<&str> = DefaultKind::ALL.iter().map(|k| k.prefix()).collect();
    assert_eq!(prefixes, ["FUN_", "LAB_", "DAT_", "EXT_"]);
    for text in [
        "FUN_",
        "FUN_x",
        "fun_00401000",
        "FUN00401000",
        "FUN_00000000000000001",
        "SUB_00401000",
        "FUN_0x401000",
    ] {
        assert_eq!(DefaultName::parse(text), None, "{text}");
    }
}
