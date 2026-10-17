//! Parser contract: the error table, the value table, depth, size and surrogates.

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod common;

use ghidorah_json::{
    Code, DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH, DEPTH_CEILING, JsonError, Limits, Number, Value,
    parse, parse_bytes, write, write_jcs, write_pretty,
};

/// Spec table: input text, expected code, expected byte offset.
const ERRORS: &[(&str, Code, usize)] = &[
    ("", Code::Eof, 0),
    ("   ", Code::Eof, 3),
    ("[", Code::Eof, 1),
    ("[1", Code::Eof, 2),
    ("[1,", Code::Eof, 3),
    ("{", Code::Eof, 1),
    ("{\"a\"", Code::Eof, 4),
    ("{\"a\":", Code::Eof, 5),
    ("\"abc", Code::Eof, 4),
    ("tru", Code::Eof, 3),
    ("nul", Code::Eof, 3),
    ("trux", Code::Syntax, 3),
    ("x", Code::Syntax, 0),
    ("[1 2]", Code::Syntax, 3),
    ("[1,]", Code::Syntax, 3),
    ("[,1]", Code::Syntax, 1),
    ("{1:2}", Code::Syntax, 1),
    ("{\"a\" 1}", Code::Syntax, 5),
    ("{\"a\":1,}", Code::Syntax, 7),
    ("{\"a\":1 \"b\":2}", Code::Syntax, 7),
    ("\u{feff}{}", Code::Syntax, 0),
    ("[\u{a0}1]", Code::Syntax, 1),
    ("\u{c}1", Code::Syntax, 0),
    (".5", Code::Syntax, 0),
    ("+1", Code::Syntax, 0),
    ("NaN", Code::Syntax, 0),
    ("Infinity", Code::Syntax, 0),
    ("01", Code::Number, 1),
    ("[-01]", Code::Number, 3),
    ("-", Code::Eof, 1),
    ("-a", Code::Number, 1),
    ("[-Infinity]", Code::Number, 2),
    ("1.", Code::Eof, 2),
    ("1.e5", Code::Number, 2),
    ("1e", Code::Eof, 2),
    ("1e+", Code::Eof, 3),
    ("[1e+]", Code::Number, 4),
    ("\"a\u{1}b\"", Code::Control, 2),
    ("\"\t\"", Code::Control, 1),
    ("\"\\x\"", Code::Escape, 1),
    ("\"\\u12G4\"", Code::Escape, 1),
    ("\"\\u12", Code::Eof, 5),
    ("\"\\", Code::Eof, 2),
    ("\"\\uD800\"", Code::Surrogate, 1),
    ("\"\\uDC00\"", Code::Surrogate, 1),
    ("\"\\uD800\\uD800\"", Code::Surrogate, 1),
    ("\"\\uD800\\n\"", Code::Surrogate, 1),
    ("\"\\uD800\\u12\"", Code::Escape, 7),
    ("\"\\uD800", Code::Eof, 7),
    ("\"\\uD800\\", Code::Eof, 8),
    ("1 2", Code::Trailing, 2),
    ("{}x", Code::Trailing, 2),
    ("[] ]", Code::Trailing, 3),
];

/// Spec table: input text and its compact write output.
const VALUES: &[(&str, &str)] = &[
    (" [ 1 , 2 ] ", "[1,2]"),
    ("{\"a\" : [true, false, null]}", "{\"a\":[true,false,null]}"),
    ("\"\\u0041\\n\\/\"", "\"A\\n/\""),
    ("\"\\uD83D\\uDE00\"", "\"\u{1f600}\""),
    (
        "\"\\u0000\\u001f\\b\\f\\r\\t\"",
        "\"\\u0000\\u001f\\b\\f\\r\\t\"",
    ),
    ("\"\\\"\\\\\"", "\"\\\"\\\\\""),
    ("-0", "-0"),
    ("1E+2", "1E+2"),
    ("0.5e-3", "0.5e-3"),
    ("\t\n\r 7", "7"),
    ("{\"a\":1,\"a\":2}", "{\"a\":1,\"a\":2}"),
    ("[]", "[]"),
    ("{}", "{}"),
    ("\"\"", "\"\""),
    (
        "\"\u{7f}\u{80}\u{e9}\u{2028}\"",
        "\"\u{7f}\u{80}\u{e9}\u{2028}\"",
    ),
    ("[[],{},[{}]]", "[[],{},[{}]]"),
];

#[test]
fn parse_error_table() {
    let limits = common::limits();
    for &(text, code, offset) in ERRORS {
        let got = parse(text, &limits);
        assert_eq!(got, Err(JsonError::new(code, offset)), "input {text:?}");
        let bytes = parse_bytes(text.as_bytes(), &limits);
        assert_eq!(bytes, Err(JsonError::new(code, offset)), "bytes {text:?}");
    }
}

#[test]
fn parse_value_table() {
    let limits = common::limits();
    for &(text, expected) in VALUES {
        let value = parse(text, &limits).unwrap_or_else(|e| panic!("{text:?}: {e}"));
        assert_eq!(write(&value), expected, "input {text:?}");
        assert_eq!(
            parse(expected, &limits).as_ref(),
            Ok(&value),
            "{expected:?}"
        );
    }
}

#[test]
fn parse_keeps_duplicates_and_order() {
    let value = parse(r#"{"b":1,"a":2,"b":3}"#, &Limits::DEFAULT).unwrap_or_default();
    let object = value.as_object().unwrap_or_else(|| panic!("an object"));
    let keys: Vec<&str> = object.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["b", "a", "b"]);
    assert_eq!(
        value.get("b").and_then(Value::as_u64),
        Some(3),
        "the last member wins"
    );
    assert_eq!(object.first_duplicate(), Some("b"));
}

#[test]
fn parse_bytes_reports_utf8_offset() {
    let limits = common::limits();
    assert_eq!(
        parse_bytes(b"[\"\xff\"]", &limits),
        Err(JsonError::new(Code::Utf8, 2))
    );
    assert_eq!(
        parse_bytes(b"[\"\xe6\x97\xa5\xd1\x88\xfa\"]", &limits),
        Err(JsonError::new(Code::Utf8, 7))
    );
    assert_eq!(
        parse_bytes("[\"\u{e9}\"]".as_bytes(), &limits),
        Ok(Value::Array(vec![Value::from("\u{e9}")]))
    );
}

#[test]
fn parse_size_limit() {
    let small = Limits {
        max_depth: DEFAULT_MAX_DEPTH,
        max_bytes: 3,
    };
    assert_eq!(
        parse("[1]", &small),
        Ok(Value::Array(vec![Value::from(1u8)]))
    );
    assert_eq!(parse("[1 ]", &small), Err(JsonError::new(Code::Size, 3)));
    assert_eq!(
        parse_bytes(b"[1 ]", &small),
        Err(JsonError::new(Code::Size, 3))
    );
    assert_eq!(
        parse_bytes(b"\xff\xff\xff\xff", &small),
        Err(JsonError::new(Code::Size, 3))
    );
    assert_eq!(Limits::default(), Limits::DEFAULT);
    assert_eq!(Limits::DEFAULT.max_bytes, DEFAULT_MAX_BYTES);
    assert_eq!(DEFAULT_MAX_BYTES, 16 * 1024 * 1024);
}

#[test]
fn error_codes_and_text() {
    let names: Vec<&str> = Code::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        names,
        [
            "E_EOF",
            "E_SYNTAX",
            "E_DEPTH",
            "E_SIZE",
            "E_NUMBER",
            "E_CONTROL",
            "E_ESCAPE",
            "E_SURROGATE",
            "E_UTF8",
            "E_TRAILING"
        ]
    );
    for code in Code::ALL {
        assert!(code.message().ends_with('.'), "{code}");
        assert_eq!(code.to_string(), code.as_str());
    }
    let e = JsonError::new(Code::Depth, 128);
    assert_eq!(
        e.to_string(),
        "E_DEPTH at byte 128: The nesting depth is more than the limit."
    );
}

#[test]
fn number_2pow53_kept_as_lexeme() {
    let limits = common::limits();
    let value = parse("9007199254740993", &limits).unwrap_or_default();
    assert_eq!(
        value.as_number().map(Number::as_str),
        Some("9007199254740993")
    );
    assert_eq!(value.as_u64(), Some(9_007_199_254_740_993));
    assert_eq!(value.as_i64(), Some(9_007_199_254_740_993));
    assert_eq!(value.as_f64(), Some(9_007_199_254_740_992.0));
    assert_eq!(write(&value), "9007199254740993");
    assert_eq!(write_jcs(&value).as_deref(), Ok("9007199254740992"));

    let max = parse("[18446744073709551615, 18446744073709551616]", &limits).unwrap_or_default();
    let items = max.as_array().unwrap_or_default();
    assert_eq!(items[0].as_u64(), Some(u64::MAX));
    assert_eq!(items[1].as_u64(), None);
    assert_eq!(write(&max), "[18446744073709551615,18446744073709551616]");

    let neg =
        parse("[-9223372036854775808, -9223372036854775809, -0]", &limits).unwrap_or_default();
    let items = neg.as_array().unwrap_or_default();
    assert_eq!(items[0].as_i64(), Some(i64::MIN));
    assert_eq!(items[1].as_i64(), None);
    assert_eq!(items[0].as_u64(), None);
    assert_eq!(items[2].as_i64(), Some(0));
    assert_eq!(items[2].as_u64(), Some(0));

    let huge = parse("[1e400, 1.0, 1e2]", &limits).unwrap_or_default();
    let items = huge.as_array().unwrap_or_default();
    assert_eq!(items[0].as_f64(), None, "outside the f64 range");
    assert_eq!(items[1].as_u64(), None, "a fraction part is not an integer");
    assert_eq!(
        items[2].as_u64(),
        None,
        "an exponent part is not an integer"
    );
    assert_eq!(items[1].as_f64(), Some(1.0));
    assert_eq!(write(&huge), "[1e400,1.0,1e2]");
}

fn nested(open: &str, depth: usize, inner: &str, close: &str) -> String {
    let mut text = open.repeat(depth);
    text.push_str(inner);
    text.push_str(&close.repeat(depth));
    text
}

fn depth_of(value: &Value) -> usize {
    let mut depth = 0;
    let mut current = value;
    loop {
        match current {
            Value::Array(items) if !items.is_empty() => current = &items[0],
            Value::Object(o) if !o.is_empty() => current = &o.members()[0].1,
            Value::Array(_) | Value::Object(_) => return depth + 1,
            _ => return depth,
        }
        depth += 1;
    }
}

#[test]
fn ac_040a_lone_surrogate_offset() {
    let limits = common::limits();
    let cases: &[(&str, usize)] = &[
        (r#"["\uD800"]"#, 2),
        (r#""ab\uDC00""#, 3),
        (r#"{"key\uD83D": 1}"#, 5),
        (r#"["ok", "x\uDBFFy"]"#, 9),
        (r#"["\uDE00\uD83D"]"#, 2),
    ];
    for &(text, offset) in cases {
        assert_eq!(
            parse(text, &limits),
            Err(JsonError::new(Code::Surrogate, offset)),
            "{text}"
        );
        assert_eq!(
            parse_bytes(text.as_bytes(), &limits).map_err(|e| (e.code.as_str(), e.offset)),
            Err(("E_SURROGATE", offset))
        );
    }
    let pair = parse(r#"["\uD83D\uDE00", "\udbff\udfff"]"#, &limits);
    assert_eq!(
        pair,
        Ok(Value::Array(vec![
            Value::from("\u{1f600}"),
            Value::from("\u{10ffff}")
        ]))
    );
}

#[test]
fn ac_040b_depth_128() {
    let limits = common::limits();
    assert_eq!(DEFAULT_MAX_DEPTH, 128);
    let ok = parse(&nested("[", 128, "", "]"), &limits).unwrap_or_default();
    assert_eq!(depth_of(&ok), 128);
    let deep = parse(&nested("[", 129, "", "]"), &limits);
    assert_eq!(deep, Err(JsonError::new(Code::Depth, 128)));
    assert_eq!(deep.map_err(|e| e.code.as_str()), Err("E_DEPTH"));

    let objects = parse(&nested("{\"a\":", 129, "1", "}"), &limits);
    assert_eq!(objects, Err(JsonError::new(Code::Depth, 5 * 128)));
    let mixed = parse(&nested("[{\"a\":", 65, "1", "}]"), &limits);
    assert_eq!(mixed.map_err(|e| e.code), Err(Code::Depth));

    let zero = Limits {
        max_depth: 0,
        max_bytes: DEFAULT_MAX_BYTES,
    };
    assert_eq!(parse("1", &zero), Ok(Value::from(1u8)));
    assert_eq!(parse("[]", &zero), Err(JsonError::new(Code::Depth, 0)));
    let two = Limits {
        max_depth: 2,
        max_bytes: DEFAULT_MAX_BYTES,
    };
    assert!(parse("[[1]]", &two).is_ok());
    assert_eq!(
        parse("[{\"a\":[1]}]", &two),
        Err(JsonError::new(Code::Depth, 6))
    );

    let unbounded = Limits {
        max_depth: usize::MAX,
        max_bytes: DEFAULT_MAX_BYTES,
    };
    assert_eq!(DEPTH_CEILING, 1024);
    let at_ceiling = parse(&nested("[", DEPTH_CEILING, "", "]"), &unbounded);
    assert!(at_ceiling.is_ok());
    let past = parse(&nested("[", DEPTH_CEILING + 1, "", "]"), &unbounded);
    assert_eq!(past, Err(JsonError::new(Code::Depth, DEPTH_CEILING)));
}

/// Runs `body` in a thread with a 256 KiB stack and gives its result.
fn small_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(body)
        .unwrap_or_else(|e| panic!("spawn: {e}"))
        .join()
        .unwrap_or_else(|_| panic!("the small-stack thread panics"))
}

#[test]
fn ac_040c_deep_nesting_small_stack() {
    let results = small_stack(|| {
        let limits = Limits::DEFAULT;
        let unbounded = Limits {
            max_depth: usize::MAX,
            max_bytes: DEFAULT_MAX_BYTES,
        };
        let closed = nested("[", 100_000, "", "]");
        let open = "[".repeat(100_000);
        let objects = nested("{\"a\":[", 50_000, "", "]}");
        let mut out = vec![
            parse(&closed, &limits),
            parse(&open, &limits),
            parse(&objects, &limits),
            parse(&closed, &unbounded),
            parse_bytes(closed.as_bytes(), &limits),
        ];
        // A value at the default limit writes, compares, copies and drops in the small stack.
        let ok = parse(&nested("[", 128, "", "]"), &limits);
        if let Ok(value) = &ok {
            let copy = value.clone();
            assert_eq!(&copy, value);
            assert_eq!(parse(&write(value), &limits).as_ref(), Ok(value));
            assert_eq!(parse(&write_pretty(value), &limits).as_ref(), Ok(value));
            assert!(write_jcs(value).is_ok());
        }
        out.push(ok.map(|_| Value::Null));
        out
    });
    assert_eq!(
        results,
        vec![
            Err(JsonError::new(Code::Depth, 128)),
            Err(JsonError::new(Code::Depth, 128)),
            Err(JsonError::new(Code::Depth, 64 * 6)),
            Err(JsonError::new(Code::Depth, DEPTH_CEILING)),
            Err(JsonError::new(Code::Depth, 128)),
            Ok(Value::Null),
        ]
    );
    let file = common::suite_dir().join("n_structure_100000_opening_arrays.json");
    let bytes = std::fs::read(&file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
    let got = small_stack(move || parse_bytes(&bytes, &Limits::DEFAULT));
    assert_eq!(got, Err(JsonError::new(Code::Depth, 128)));
}
