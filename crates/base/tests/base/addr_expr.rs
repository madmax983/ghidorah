//! Tests of the address syntax (design Section 10.5, ADR-0007, AC-046a and AC-046b).

use ghidorah_base::addr_expr::{
    self, JSON_INT_LIMIT, MAX_EXPR_LEN, NameAt, NameExpr, OffsetExpr, OffsetValue, Readings,
};
use ghidorah_base::{
    AddrExpr, AddrExprError, Address, DefaultKind, DefaultName, FuncId, Id, IdError, IdKind,
    ImportId, SymId,
};

fn name(text: &str) -> NameExpr {
    NameExpr {
        text: text.to_string(),
        default: None,
        at: None,
        split: None,
        bare_hex: None,
    }
}

fn offset(term: AddrExpr, negative: bool, value: u64) -> OffsetExpr {
    OffsetExpr {
        term: Box::new(term),
        negative,
        offset: OffsetValue::Hex(value),
    }
}

fn digits(decimal: Option<u64>, hex: Option<u64>) -> Readings {
    Readings { decimal, hex }
}

#[test]
fn ac_046a_address_syntax() {
    let main_plus = NameExpr {
        split: Some(offset(AddrExpr::Name(name("main")), false, 0x10)),
        ..name("main+0x10")
    };
    let cases: Vec<(&str, AddrExpr)> = vec![
        // Rule 2: hex.
        ("0x401000", AddrExpr::Hex(0x40_1000)),
        ("0x0", AddrExpr::Hex(0)),
        ("0xFFFFffffFFFFffff", AddrExpr::Hex(u64::MAX)),
        ("  0x401000\t", AddrExpr::Hex(0x40_1000)),
        // Rule 3: registered ID prefixes, as an exact parse.
        (
            "fn:0x401130",
            AddrExpr::Id(Id::Func(FuncId(Address::ram(0x40_1130)))),
        ),
        ("ext:0x3", AddrExpr::Id(Id::External(3))),
        ("imp:puts", AddrExpr::Id(Id::Import(ImportId::elf("puts").unwrap()))),
        (
            "sym:puts@GLIBC_2.2.5",
            AddrExpr::Id(Id::Sym(SymId::new("puts@GLIBC_2.2.5").unwrap())),
        ),
        // `sym:` takes the whole rest and skips every other rule.
        (
            "sym:main+0x10",
            AddrExpr::Id(Id::Sym(SymId::new("main+0x10").unwrap())),
        ),
        // Rule 4 and 5: a symbol name or a section name, with `@` and `.`.
        ("main", AddrExpr::Name(name("main"))),
        ("puts@GLIBC_2.2.5", AddrExpr::Name(name("puts@GLIBC_2.2.5"))),
        ("x@plt", AddrExpr::Name(name("x@plt"))),
        ("foo.cold", AddrExpr::Name(name("foo.cold"))),
        (".text", AddrExpr::Name(name(".text"))),
        ("operator+", AddrExpr::Name(name("operator+"))),
        ("foo-bar", AddrExpr::Name(name("foo-bar"))),
        // Rule 6: a default name.
        (
            "FUN_00401000",
            AddrExpr::Name(NameExpr {
                default: Some(DefaultName {
                    kind: DefaultKind::Fun,
                    addr: Address::ram(0x40_1000),
                }),
                ..name("FUN_00401000")
            }),
        ),
        // Rule 7: name@0x<hex>.
        (
            "helper@0x401000",
            AddrExpr::Name(NameExpr {
                at: Some(NameAt {
                    name: "helper".to_string(),
                    addr: 0x40_1000,
                }),
                ..name("helper@0x401000")
            }),
        ),
        (
            "a@b@0x10",
            AddrExpr::Name(NameExpr {
                at: Some(NameAt {
                    name: "a@b".to_string(),
                    addr: 0x10,
                }),
                ..name("a@b@0x10")
            }),
        ),
        // Rule 8: term+0x.. or term-0x.., split at the last sign.
        ("main+0x10", AddrExpr::Name(main_plus)),
        (
            "a-b-0x4",
            AddrExpr::Name(NameExpr {
                split: Some(offset(AddrExpr::Name(name("a-b")), true, 4)),
                ..name("a-b-0x4")
            }),
        ),
        (
            "0x401000+0x10",
            AddrExpr::Offset(offset(AddrExpr::Hex(0x40_1000), false, 0x10)),
        ),
        (
            "fn:0x401000-0x4",
            AddrExpr::Offset(offset(
                AddrExpr::Id(Id::Func(FuncId(Address::ram(0x40_1000)))),
                true,
                4,
            )),
        ),
        (
            "ext:0x10+0x1",
            AddrExpr::Offset(offset(AddrExpr::Id(Id::External(0x10)), false, 1)),
        ),
        (
            "FUN_00401000+0x8",
            AddrExpr::Name(NameExpr {
                split: Some(offset(
                    AddrExpr::Name(NameExpr {
                        default: Some(DefaultName {
                            kind: DefaultKind::Fun,
                            addr: Address::ram(0x40_1000),
                        }),
                        ..name("FUN_00401000")
                    }),
                    false,
                    8,
                )),
                ..name("FUN_00401000+0x8")
            }),
        ),
        (
            "helper@0x401000+0x4",
            AddrExpr::Name(NameExpr {
                split: Some(offset(
                    AddrExpr::Name(NameExpr {
                        at: Some(NameAt {
                            name: "helper".to_string(),
                            addr: 0x40_1000,
                        }),
                        ..name("helper@0x401000")
                    }),
                    false,
                    4,
                )),
                ..name("helper@0x401000+0x4")
            }),
        ),
        // A text of hex digits with a letter keeps its value for the repair call.
        (
            "deadbeef",
            AddrExpr::Name(NameExpr {
                bare_hex: Some(0xdead_beef),
                ..name("deadbeef")
            }),
        ),
    ];
    for (text, want) in cases {
        assert_eq!(addr_expr::parse(text), Ok(want), "{text:?}");
    }
    // Rule 1: a JSON integer below 2^53.
    assert_eq!(addr_expr::from_integer(0), Ok(AddrExpr::Integer(0)));
    assert_eq!(
        addr_expr::from_integer(JSON_INT_LIMIT - 1),
        Ok(AddrExpr::Integer(JSON_INT_LIMIT - 1))
    );
}

#[test]
fn ac_046b_digits_only() {
    let cases = [
        ("401000", digits(Some(401_000), Some(0x40_1000))),
        ("0", digits(Some(0), Some(0))),
        ("16", digits(Some(16), Some(0x16))),
        ("0000000000000010", digits(Some(10), Some(0x10))),
        ("18446744073709551615", digits(Some(u64::MAX), None)),
        ("18446744073709551616", digits(None, None)),
        ("99999999999999999999999", digits(None, None)),
    ];
    for (text, want) in cases {
        assert_eq!(addr_expr::parse(text), Ok(AddrExpr::Digits(want)), "{text}");
    }
    // A decimal offset is ambiguous too.
    let want = NameExpr {
        split: Some(OffsetExpr {
            term: Box::new(AddrExpr::Name(name("main"))),
            negative: false,
            offset: OffsetValue::Digits(digits(Some(16), Some(0x16))),
        }),
        ..name("main+16")
    };
    assert_eq!(addr_expr::parse("main+16"), Ok(AddrExpr::Name(want)));
    let hex_term = OffsetExpr {
        term: Box::new(AddrExpr::Hex(0x40_1000)),
        negative: true,
        offset: OffsetValue::Digits(digits(Some(8), Some(8))),
    };
    assert_eq!(addr_expr::parse("0x401000-8"), Ok(AddrExpr::Offset(hex_term)));
}

#[test]
fn addr_expr_errors() {
    let long = format!("0x{}", "0".repeat(MAX_EXPR_LEN));
    let cases: Vec<(&str, AddrExprError)> = vec![
        ("", AddrExprError::Empty),
        ("   ", AddrExprError::Empty),
        (long.as_str(), AddrExprError::TooLong { len: long.len() }),
        ("0x", AddrExprError::BadHex),
        ("0xg", AddrExprError::BadHex),
        ("0x10000000000000000", AddrExprError::BadHex),
        ("0x1+0x2+0x3", AddrExprError::BadHex),
        ("0x1+main", AddrExprError::BadHex),
        (
            "fn:main",
            AddrExprError::BadId(IdError::BadPart {
                kind: Some(IdKind::Func),
                part: "address",
            }),
        ),
        (
            "fn:main+0x4",
            AddrExprError::BadId(IdError::BadPart {
                kind: Some(IdKind::Func),
                part: "address",
            }),
        ),
        (
            "sym:",
            AddrExprError::BadId(IdError::BadPart {
                kind: Some(IdKind::Sym),
                part: "name",
            }),
        ),
    ];
    for (text, want) in cases {
        assert_eq!(addr_expr::parse(text), Err(want), "{text:.40}");
    }
    assert_eq!(
        addr_expr::from_integer(JSON_INT_LIMIT),
        Err(AddrExprError::IntegerTooLarge(JSON_INT_LIMIT))
    );
    let err = AddrExprError::IntegerTooLarge(0xffff_ffff_8100_0123);
    assert_eq!(err.repair_text().as_deref(), Some("0xffffffff81000123"));
    assert_eq!(AddrExprError::BadHex.repair_text(), None);
    assert_eq!(err.code().name(), "ADDRESS_INVALID");
    for e in [
        AddrExprError::Empty,
        AddrExprError::TooLong { len: 9 },
        AddrExprError::BadHex,
        AddrExprError::BadId(IdError::Empty),
        err,
    ] {
        assert!(e.to_string().ends_with('.'), "{e}");
    }
}
