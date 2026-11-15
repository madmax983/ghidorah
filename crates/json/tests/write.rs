//! Writer contract: escapes, pretty layout, round trips and no `NaN` or `inf`.

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod common;

use ghidorah_json::{JcsErrorKind, Number, Value, parse, write, write_jcs, write_pretty};
use ghidorah_testkit::pbt;
use std::fmt::Write as _;

/// Spec table: string value and its written text.
const ESCAPES: &[(&str, &str)] = &[
    ("a\"b", r#""a\"b""#),
    ("\\", r#""\\""#),
    ("\u{0}", r#""\u0000""#),
    ("\u{8}\u{9}\u{a}\u{c}\u{d}", r#""\b\t\n\f\r""#),
    ("\u{b}", r#""\u000b""#),
    ("\u{1f}", r#""\u001f""#),
    ("\u{7f}", "\"\u{7f}\""),
    ("/", r#""/""#),
    ("\u{e9}\u{20ac}\u{1f600}", "\"\u{e9}\u{20ac}\u{1f600}\""),
    ("\u{2028}", "\"\u{2028}\""),
];

#[test]
fn write_escape_table() {
    for &(text, expected) in ESCAPES {
        let value = Value::from(text);
        assert_eq!(write(&value), expected, "{text:?}");
        assert_eq!(write_jcs(&value).as_deref(), Ok(expected), "{text:?}");
        assert_eq!(parse(expected, &common::limits()), Ok(value));
    }
}

#[test]
fn write_pretty_layout() {
    let value = Value::object([
        (
            "a",
            Value::Array(vec![Value::from(1u8), Value::object([("b", Value::Null)])]),
        ),
        ("c", Value::object(Vec::<(String, Value)>::new())),
        ("d", Value::Array(Vec::new())),
        ("e", Value::from("x")),
    ]);
    let expected = "{\n  \"a\": [\n    1,\n    {\n      \"b\": null\n    }\n  ],\n  \"c\": {},\n  \"d\": [],\n  \"e\": \"x\"\n}";
    assert_eq!(write_pretty(&value), expected);
    assert_eq!(
        write(&value),
        r#"{"a":[1,{"b":null}],"c":{},"d":[],"e":"x"}"#
    );
    assert_eq!(value.to_string(), write(&value));
    assert_eq!(write_pretty(&Value::from(true)), "true");
    assert_eq!(write_pretty(&Value::Null), "null");
}

#[test]
fn ac_041a_roundtrip() {
    let limits = common::limits();
    pbt::check("json_roundtrip", 2000, |g| {
        let value = common::value(g, 4);
        let text = write(&value);
        let back = parse(&text, &limits).map_err(|e| format!("{text}: {e}"))?;
        if back != value {
            return Err(format!("write then parse differs: {text}"));
        }
        let pretty = write_pretty(&value);
        let back = parse(&pretty, &limits).map_err(|e| format!("{pretty}: {e}"))?;
        if back != value {
            return Err(format!("pretty write then parse differs: {pretty}"));
        }
        if value.to_string() != text {
            return Err("Display differs from write".to_owned());
        }
        Ok(())
    });
}

#[test]
fn ac_041a_roundtrip_jcs() {
    let limits = common::limits();
    pbt::check("json_roundtrip_jcs", 1000, |g| {
        let value = common::jcs_value(g, 3);
        let text = write_jcs(&value).map_err(|e| e.to_string())?;
        let back = parse(&text, &limits).map_err(|e| format!("{text}: {e}"))?;
        let again = write_jcs(&back).map_err(|e| e.to_string())?;
        if again != text {
            return Err(format!("JCS is not stable: {text} then {again}"));
        }
        Ok(())
    });
}

/// Tells if a number lexeme has only grammar bytes.
fn grammar_bytes(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.' | b'e' | b'E'))
}

#[test]
fn ac_041b_no_nan_inf() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -f64::NAN] {
        assert_eq!(Number::from_f64(bad), None, "{bad}");
        assert_eq!(Value::from_f64(bad), None, "{bad}");
    }
    let edges = [
        0.0,
        -0.0,
        0.1,
        1.0,
        -1.5,
        1e21,
        1e-7,
        f64::MAX,
        f64::MIN,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::EPSILON,
        9_007_199_254_740_993.0,
    ];
    for x in edges {
        let number = Number::from_f64(x).unwrap_or_else(|| panic!("{x} is finite"));
        assert!(grammar_bytes(number.as_str()), "{number}");
        assert_eq!(Number::parse(number.as_str()).as_ref(), Ok(&number));
        let back = number.as_f64().unwrap_or(f64::NAN);
        assert_eq!(back.to_bits(), x.to_bits(), "{x} reads back as {back}");
    }
    pbt::check("json_no_nan_inf", 10_000, |g| {
        let x = f64::from_bits(g.u64());
        match Number::from_f64(x) {
            None if x.is_finite() => Err(format!("{x} is finite")),
            None => Ok(()),
            Some(_) if !x.is_finite() => Err(format!("{x} must give None")),
            Some(number) => {
                let text = write(&Value::Number(number.clone()));
                if !grammar_bytes(&text) || Number::parse(&text).is_err() {
                    return Err(format!("bad lexeme {text}"));
                }
                let back = number.as_f64().map(f64::to_bits);
                if back != Some(x.to_bits()) {
                    return Err(format!("{x} reads back as {back:?}"));
                }
                let jcs = write_jcs(&Value::Number(number)).map_err(|e| e.to_string())?;
                if !grammar_bytes(&jcs) {
                    return Err(format!("bad JCS number {jcs}"));
                }
                Ok(())
            }
        }
    });
    let huge = parse("[1e400]", &common::limits()).unwrap_or_default();
    assert_eq!(write(&huge), "[1e400]");
    assert_eq!(
        write_jcs(&huge).map_err(|e| (e.kind, e.path)),
        Err((JcsErrorKind::NumberRange, "/0".to_owned()))
    );
}

/// Gives the written text of `text` by the escape rules, one character at a time.
fn reference_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0}'..='\u{1f}' => write!(out, "\\u{:04x}", u32::from(c)).unwrap_or(()),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A byte that needs an escape gets it at each position of strings of 0 to 70 bytes.
/// The lengths cross the 8-byte and 32-byte steps of a scan.
#[test]
fn write_escape_at_each_position() {
    let specials = [
        '"', '\\', '\u{0}', '\u{8}', '\n', '\u{1f}', ' ', '\u{7f}', '\u{e9}',
    ];
    for len in 0..=70 {
        let plain = "a".repeat(len);
        let value = Value::from(plain.as_str());
        assert_eq!(write(&value), reference_string(&plain), "{len}");
        for special in specials {
            for at in 0..=len {
                let mut text = plain.clone();
                text.insert(at, special);
                let value = Value::from(text.as_str());
                let want = reference_string(&text);
                assert_eq!(write(&value), want, "{text:?}");
                assert_eq!(write_jcs(&value).as_deref(), Ok(want.as_str()), "{text:?}");
            }
        }
    }
}
