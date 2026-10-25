//! JCS contract (RFC 8785): member order, number form, string form and errors.

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod common;

use ghidorah_json::{JcsError, JcsErrorKind, Number, Object, Value, parse, write_jcs};
use ghidorah_testkit::pbt::{self, Gen};

/// RFC 8785 Appendix B: f64 bit patterns and their JCS text.
const RFC_NUMBERS: &[(u64, &str)] = &[
    (0x0000_0000_0000_0000, "0"),
    (0x8000_0000_0000_0000, "0"),
    (0x0000_0000_0000_0001, "5e-324"),
    (0x8000_0000_0000_0001, "-5e-324"),
    (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
    (0xffef_ffff_ffff_ffff, "-1.7976931348623157e+308"),
    (0x4340_0000_0000_0000, "9007199254740992"),
    (0xc340_0000_0000_0000, "-9007199254740992"),
    (0x4430_0000_0000_0000, "295147905179352830000"),
    (0x44b5_2d02_c7e1_4af5, "9.999999999999997e+22"),
    (0x44b5_2d02_c7e1_4af6, "1e+23"),
    (0x44b5_2d02_c7e1_4af7, "1.0000000000000001e+23"),
    (0x444b_1ae4_d6e2_ef4e, "999999999999999700000"),
    (0x444b_1ae4_d6e2_ef4f, "999999999999999900000"),
    (0x444b_1ae4_d6e2_ef50, "1e+21"),
    (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
    (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
    (0x41b3_de43_5555_5553, "333333333.3333332"),
    (0x41b3_de43_5555_5554, "333333333.33333325"),
    (0x41b3_de43_5555_5555, "333333333.3333333"),
    (0x41b3_de43_5555_5556, "333333333.3333334"),
    (0x41b3_de43_5555_5557, "333333333.33333343"),
    (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
    (0x4314_3ff3_c1cb_0959, "1424953923781206.2"),
];

fn number_of_bits(bits: u64) -> Number {
    Number::from_f64(f64::from_bits(bits)).unwrap_or_else(|| panic!("{bits:#x} is finite"))
}

#[test]
fn jcs_number_vectors() {
    for &(bits, expected) in RFC_NUMBERS {
        let number = number_of_bits(bits);
        assert_eq!(number.to_jcs().as_deref(), Some(expected), "{bits:#018x}");
        let text = write_jcs(&Value::Number(number));
        assert_eq!(text.as_deref(), Ok(expected), "{bits:#018x}");
    }
    // Lexemes that are not in the shortest form give the form of their nearest f64.
    for (lexeme, expected) in [
        ("4.50", "4.5"),
        ("1E30", "1e+30"),
        ("2e-3", "0.002"),
        ("0.000000000000000000000000001", "1e-27"),
        ("-0.0", "0"),
        ("100", "100"),
        ("1e-400", "0"),
        ("123456789012345678901234567890", "1.2345678901234568e+29"),
    ] {
        let number = Number::parse(lexeme).unwrap_or_else(|e| panic!("{lexeme}: {e}"));
        assert_eq!(number.to_jcs().as_deref(), Some(expected), "{lexeme}");
    }
    assert_eq!(Number::parse("1e400").ok().and_then(|n| n.to_jcs()), None);
}

#[test]
fn jcs_number_table_matches_ecmascript() {
    let table = include_str!("data/jcs_numbers.txt");
    let mut rows = 0;
    for line in table.lines().filter(|l| !l.starts_with('#')) {
        let (hex, expected) = line
            .split_once(' ')
            .unwrap_or_else(|| panic!("bad row {line:?}"));
        let bits = u64::from_str_radix(hex, 16).unwrap_or_else(|e| panic!("{hex}: {e}"));
        let number = number_of_bits(bits);
        assert_eq!(number.to_jcs().as_deref(), Some(expected), "{hex}");
        rows += 1;
    }
    assert_eq!(rows, 1000);
}

#[test]
fn jcs_rfc8785_examples() {
    let limits = common::limits();
    let input = r#"{
        "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
        "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
        "literals": [null, true, false]
    }"#;
    let value = parse(input, &limits).unwrap_or_else(|e| panic!("{e}"));
    let expected = concat!(
        r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"#,
        "\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
    );
    assert_eq!(write_jcs(&value).as_deref(), Ok(expected));

    let sorting = r#"{
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\ud83d\ude00": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis"
    }"#;
    let value = parse(sorting, &limits).unwrap_or_else(|e| panic!("{e}"));
    let expected = concat!(
        "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",",
        "\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",",
        "\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
    );
    assert_eq!(write_jcs(&value).as_deref(), Ok(expected));
}

/// Gives every order of `items` (Heap's algorithm, no recursion).
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    let mut items = items.to_vec();
    let mut c = vec![0usize; items.len()];
    let mut out = vec![items.clone()];
    let mut i = 0;
    while i < items.len() {
        if c[i] < i {
            if i % 2 == 0 {
                items.swap(0, i);
            } else {
                items.swap(c[i], i);
            }
            out.push(items.clone());
            c[i] += 1;
            i = 0;
        } else {
            c[i] = 0;
            i += 1;
        }
    }
    out
}

/// Gives a copy of `value` with the members of each object in a random order.
fn shuffle(g: &mut Gen, value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(|v| shuffle(g, v)).collect()),
        Value::Object(object) => {
            let mut members: Vec<(String, Value)> = object
                .iter()
                .map(|(k, v)| (k.to_owned(), shuffle(g, v)))
                .collect();
            for i in (1..members.len()).rev() {
                let j = usize::try_from(g.draw(u64::try_from(i + 1).unwrap_or(1))).unwrap_or(0);
                members.swap(i, j);
            }
            Value::object(members)
        }
        other => other.clone(),
    }
}

#[test]
fn ac_042_jcs_canonical() {
    let members = vec![
        ("b", Value::from(1u8)),
        (
            "a",
            Value::object([("y", Value::Null), ("x", Value::from(true))]),
        ),
        ("\u{1f600}", Value::from("emoji")),
        ("\u{fb33}", Value::from("dalet")),
        (
            "",
            Value::Array(vec![
                Value::from(2u8),
                Value::object([("k", Value::from(3u8))]),
            ]),
        ),
        ("aa", Value::from(-1i8)),
    ];
    let all = permutations(&members);
    assert_eq!(all.len(), 720);
    let first = write_jcs(&Value::object(members.clone())).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        first,
        concat!(
            r#"{"":[2,{"k":3}],"a":{"x":true,"y":null},"aa":-1,"b":1,"#,
            "\"\u{1f600}\":\"emoji\",\"\u{fb33}\":\"dalet\"}"
        )
    );
    for order in &all {
        let text = write_jcs(&Value::object(order.clone()));
        assert_eq!(text.as_deref(), Ok(first.as_str()), "{order:?}");
    }
    pbt::check("jcs_member_order", 500, |g| {
        let value = Value::Object(common::unique_object(g, 3));
        let mixed = shuffle(g, &value);
        let a = write_jcs(&value).map_err(|e| e.to_string())?;
        let b = write_jcs(&mixed).map_err(|e| e.to_string())?;
        if a == b {
            Ok(())
        } else {
            Err(format!("{a} differs from {b}"))
        }
    });
}

#[test]
fn jcs_errors_name_the_path() {
    let limits = common::limits();
    let dup = parse(r#"{"a":[{"b":1,"b":2}]}"#, &limits).unwrap_or_default();
    let err = write_jcs(&dup);
    assert_eq!(
        err,
        Err(JcsError {
            kind: JcsErrorKind::DuplicateKey,
            path: "/a/0/b".to_owned(),
        })
    );
    assert_eq!(
        err.map_err(|e| e.to_string()),
        Err("E_DUPLICATE_KEY at '/a/0/b': the object has two members with this name".to_owned())
    );
    let range = parse(r#"{"x~/y":[0, -1e999]}"#, &limits).unwrap_or_default();
    let err = write_jcs(&range).map_err(|e| (e.kind.as_str(), e.path));
    assert_eq!(err, Err(("E_NUMBER_RANGE", "/x~0~1y/1".to_owned())));
    assert_eq!(
        write_jcs(&range).map_err(|e| e.to_string()),
        Err("E_NUMBER_RANGE at '/x~0~1y/1': the number is outside the f64 range".to_owned())
    );
    let mut object = Object::new();
    object.push("k", Value::from(1u8));
    object.push("k", Value::from(1u8));
    assert_eq!(
        write_jcs(&Value::Object(object)).map_err(|e| e.path),
        Err("/k".to_owned())
    );
    assert_eq!(write_jcs(&Value::Null).as_deref(), Ok("null"));
}

#[test]
fn jcs_plain_matches_the_f64_form_of_short_integers() {
    for lexeme in ["0", "7", "-7", "10", "123456789012345", "-999999999999999"] {
        let number = Number::parse(lexeme).expect("lexeme");
        let value = number.as_f64().expect("finite");
        assert_eq!(number.jcs_plain(), Some(lexeme));
        assert_eq!(format!("{value}"), lexeme);
    }
    for lexeme in ["-0", "1.0", "1e3", "1234567890123456", "-1234567890123456"] {
        let number = Number::parse(lexeme).expect("lexeme");
        assert_eq!(number.jcs_plain(), None, "{lexeme}");
    }
}
