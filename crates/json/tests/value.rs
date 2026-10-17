//! Value contract: object members, accessors and number conversions.

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod common;

use ghidorah_json::{Code, JsonError, Number, Object, Value, parse};

#[test]
fn object_members_keep_order() {
    let mut object = Object::new();
    assert!(object.is_empty());
    object.push("b", Value::from(1u8));
    object.push("a", Value::from(2u8));
    object.push("b", Value::from(3u8));
    assert_eq!(object.len(), 3);
    assert_eq!(
        object.get("b"),
        Some(&Value::from(3u8)),
        "the last member wins"
    );
    assert_eq!(object.first_duplicate(), Some("b"));
    assert!(object.contains_key("a"));
    assert!(!object.contains_key("c"));
    assert_eq!(object.insert("b", Value::from(4u8)), Some(Value::from(3u8)));
    assert_eq!(object.insert("c", Value::from(5u8)), None);
    let keys: Vec<&str> = object.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["b", "a", "b", "c"]);
    assert_eq!(object.members()[0].1, Value::from(1u8));
    assert_eq!(object.members()[2].1, Value::from(4u8));
    if let Some(v) = object.get_mut("a") {
        *v = Value::Null;
    }
    assert_eq!(object.get("a"), Some(&Value::Null));
    assert_eq!(object.get_mut("zz"), None);
    assert_eq!(object.remove("b"), Some(Value::from(4u8)));
    assert_eq!(object.remove("b"), None);
    assert_eq!(object.first_duplicate(), None);
    let pairs: Vec<(String, Value)> = object.clone().into_iter().collect();
    assert_eq!(pairs, object.clone().into_members());
    assert_eq!(Value::Object(object).to_string(), r#"{"a":null,"c":5}"#);
    let collected: Object = [("x", Value::Null), ("y", Value::from(true))]
        .into_iter()
        .collect();
    assert_eq!(
        Value::Object(collected).to_string(),
        r#"{"x":null,"y":true}"#
    );
}

#[test]
fn value_accessors() {
    let mut value = parse(
        r#"{"s":"text","n":-12,"f":2.5,"b":true,"z":null,"a":[1],"o":{"k":"v"}}"#,
        &common::limits(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let get = |key: &str| value.get(key).cloned().unwrap_or_else(|| panic!("{key}"));
    assert_eq!(get("s").as_str(), Some("text"));
    assert_eq!(get("n").as_i64(), Some(-12));
    assert_eq!(get("n").as_u64(), None);
    assert_eq!(get("f").as_f64().map(f64::to_bits), Some(2.5f64.to_bits()));
    assert_eq!(get("b").as_bool(), Some(true));
    assert!(get("z").is_null());
    assert_eq!(get("a").as_array().map(<[Value]>::len), Some(1));
    assert_eq!(get("o").as_object().map(Object::len), Some(1));
    assert_eq!(get("o").get("k").and_then(Value::as_str), Some("v"));
    assert_eq!(get("s").as_bool(), None);
    assert_eq!(get("s").as_number(), None);
    assert_eq!(get("s").as_array(), None);
    assert_eq!(get("s").as_object(), None);
    assert_eq!(get("s").get("k"), None);
    assert_eq!(get("b").as_str(), None);
    assert_eq!(value.pointer("/o/k").and_then(Value::as_str), Some("v"));
    assert_eq!(value.pointer("o"), None);
    let kinds: Vec<&str> = ["z", "b", "n", "s", "a", "o"]
        .iter()
        .map(|k| get(k).kind())
        .collect();
    assert_eq!(
        kinds,
        ["null", "bool", "number", "string", "array", "object"]
    );
    if let Some(items) = value
        .as_object_mut()
        .and_then(|o| o.get_mut("a"))
        .and_then(Value::as_array_mut)
    {
        items.push(Value::from(2u8));
    }
    assert_eq!(value.pointer("/a/1"), Some(&Value::from(2u8)));
    assert_eq!(Value::Null.as_array_mut(), None);
    assert_eq!(Value::Null.as_object_mut(), None);
    assert_eq!(Value::default(), Value::Null);
}

#[test]
fn value_from_impls() {
    assert_eq!(Value::from(true).to_string(), "true");
    assert_eq!(Value::from("a").to_string(), r#""a""#);
    assert_eq!(Value::from("a".to_owned()).to_string(), r#""a""#);
    assert_eq!(Value::from(Some(3u8)).to_string(), "3");
    assert_eq!(Value::from(None::<u8>).to_string(), "null");
    assert_eq!(Value::from(vec![Value::Null]).to_string(), "[null]");
    assert_eq!(Value::from(Object::new()).to_string(), "{}");
    assert_eq!(Value::from(Number::from(7u8)).to_string(), "7");
    let ints = [
        Value::from(u8::MAX),
        Value::from(u16::MAX),
        Value::from(u32::MAX),
        Value::from(u64::MAX),
        Value::from(usize::MAX),
        Value::from(i8::MIN),
        Value::from(i16::MIN),
        Value::from(i32::MIN),
        Value::from(i64::MIN),
        Value::from(isize::MIN),
    ];
    let text: Vec<String> = ints.iter().map(Value::to_string).collect();
    assert_eq!(
        text,
        [
            "255".to_owned(),
            "65535".to_owned(),
            "4294967295".to_owned(),
            "18446744073709551615".to_owned(),
            usize::MAX.to_string(),
            "-128".to_owned(),
            "-32768".to_owned(),
            "-2147483648".to_owned(),
            "-9223372036854775808".to_owned(),
            isize::MIN.to_string(),
        ]
    );
    assert_eq!(
        Value::from_f64(0.5).map(|v| v.to_string()).as_deref(),
        Some("0.5")
    );
}

#[test]
fn number_grammar() {
    for good in [
        "0",
        "-0",
        "1",
        "-12",
        "1.5",
        "1e5",
        "1E+5",
        "1e-05",
        "0.0",
        "123.456e789",
    ] {
        let number = Number::parse(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        assert_eq!(number.as_str(), good);
        assert_eq!(number.to_string(), good);
        assert_eq!(good.parse::<Number>().as_ref(), Ok(&number));
    }
    let bad: &[(&str, Code, usize)] = &[
        ("", Code::Eof, 0),
        ("-", Code::Eof, 1),
        ("01", Code::Number, 1),
        ("1.", Code::Eof, 2),
        (".1", Code::Number, 0),
        ("1e", Code::Eof, 2),
        ("+1", Code::Number, 0),
        (" 1", Code::Number, 0),
        ("1 ", Code::Trailing, 1),
        ("1x", Code::Trailing, 1),
        ("NaN", Code::Number, 0),
    ];
    for &(text, code, offset) in bad {
        assert_eq!(
            Number::parse(text),
            Err(JsonError::new(code, offset)),
            "{text:?}"
        );
    }
    let int = Number::parse("42").unwrap_or_else(|e| panic!("{e}"));
    assert!(int.is_integer());
    assert!(!Number::parse("4.2").is_ok_and(|n| n.is_integer()));
    assert!(!Number::parse("4e2").is_ok_and(|n| n.is_integer()));
    assert_eq!(Number::from(-5i32).as_i64(), Some(-5));
    assert_eq!(Number::from(5u32).as_u64(), Some(5));
    assert_eq!(Number::parse("1.5").ok().and_then(|n| n.as_i64()), None);
    assert_eq!(
        Number::from(5u32).as_f64().map(f64::to_bits),
        Some(5f64.to_bits())
    );
}
