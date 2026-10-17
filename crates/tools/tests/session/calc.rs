//! `calc`: operators, views, depth and errors (AC-158a, AC-158b).

use ghidorah_json::Value;
use ghidorah_tools::calc::{MAX_DEPTH, eval, signed_text, views};
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::{ToolError, handlers};

use crate::support::{
    DEMO_MAIN, add_function, call, call_value, code, data, demo, session, text_at,
};

/// Each operator with one expression and its value.
const OPERATORS: [(&str, u64); 17] = [
    ("0x10 + 0x20", 0x30),
    ("0x10 - 0x20", 0xffff_ffff_ffff_fff0),
    ("0x7 * 0x6", 42),
    ("0x64 / 0x7", 14),
    ("0x64 % 0x7", 2),
    ("0x1 << 0x4", 16),
    ("0x100 >> 0x4", 16),
    ("0xf0 & 0x3c", 0x30),
    ("0xf0 | 0x0f", 0xff),
    ("0xff ^ 0x0f", 0xf0),
    ("~0x0", u64::MAX),
    ("-0x1", u64::MAX),
    ("+0x5", 5),
    ("(0x1 + 0x2) * 0x3", 9),
    ("0x1 + 0x2 * 0x3", 7),
    ("0x1 << 0x40", 0),
    ("0xffffffffffffffff + 0x1", 0),
];

/// Values with all their views: `(value, [u8, u16, u32, u64, i8, i16, i32, i64])`.
const VIEWS: [(u64, [&str; 8]); 3] = [
    (
        u64::MAX,
        [
            "255",
            "65535",
            "4294967295",
            "18446744073709551615",
            "-1",
            "-1",
            "-1",
            "-1",
        ],
    ),
    (
        0x1234_5678_9abc_def0,
        [
            "240",
            "57072",
            "2596069104",
            "1311768467463790320",
            "-16",
            "-8464",
            "-1698898192",
            "1311768467463790320",
        ],
    ),
    (
        0x80,
        ["128", "128", "128", "128", "-128", "128", "128", "128"],
    ),
];

fn calc(session: &mut ghidorah_tools::Session, expr: &str) -> Value {
    call_value(
        session,
        "calc",
        Value::object([("expr", Value::from(expr))]),
    )
}

#[test]
fn ac_158a_calc_views() {
    let mut s = session();
    for (expr, want) in OPERATORS {
        let envelope = calc(&mut s, expr);
        let got = data(&envelope);
        assert_eq!(text_at(got, "/value"), format!("{want:#x}"), "{expr}");
        assert_eq!(text_at(got, "/unsigned"), want.to_string(), "{expr}");
        assert_eq!(text_at(got, "/signed"), signed_text(want), "{expr}");
        assert_eq!(got.get("views"), Some(&views(want)), "{expr}");
        assert!(
            got.get("address").is_none(),
            "no binary, no address: {expr}"
        );
        handlers::calc::SPEC
            .output
            .check(got, Fit::Exact)
            .unwrap_or_else(|e| panic!("{expr}: {e}"));
    }
    for (value, want) in VIEWS {
        let got = views(value);
        for (name, text) in ghidorah_tools::calc::VIEWS.iter().zip(want) {
            assert_eq!(
                text_at(&got, &format!("/{name}")),
                text,
                "{value:#x} {name}"
            );
        }
    }
    assert_eq!(signed_text(u64::MAX), "-1");
    assert_eq!(signed_text(0x8000_0000_0000_0000), "-9223372036854775808");
    assert_eq!(signed_text(7), "7");
}

#[test]
fn ac_158b_calc_depth_64() {
    let mut no_names = |_: &str| -> Result<u64, ToolError> {
        Err(ToolError::new(ghidorah_base::ErrorCode::NoBinaryOpen))
    };
    let nest = |n: usize| format!("{}0x1{}", "(".repeat(n), ")".repeat(n));
    assert_eq!(eval(&nest(MAX_DEPTH), &mut no_names).ok(), Some(1));
    let deep = eval(&nest(MAX_DEPTH + 1), &mut no_names).expect_err("too deep");
    assert_eq!(deep.code, ghidorah_base::ErrorCode::InvalidArgument);
    let unary = |n: usize| format!("{}0x1", "~".repeat(n));
    assert_eq!(eval(&unary(MAX_DEPTH), &mut no_names).ok(), Some(1));
    assert!(eval(&unary(MAX_DEPTH + 1), &mut no_names).is_err());
    let mixed = format!("{}0x2{}", "(-".repeat(32), ")".repeat(32));
    assert_eq!(eval(&mixed, &mut no_names).ok(), Some(2));
    let mixed_deep = format!("{}0x2{}", "(-".repeat(33), ")".repeat(33));
    assert!(eval(&mixed_deep, &mut no_names).is_err());
    let long_flat = vec!["0x1"; 200].join("+");
    assert_eq!(eval(&long_flat, &mut no_names).ok(), Some(200));

    let mut s = session();
    let envelope = calc(&mut s, &nest(MAX_DEPTH + 1));
    assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{envelope}");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/expr");
    let envelope = calc(&mut s, &nest(400));
    assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{envelope}");
}

#[test]
fn calc_errors() {
    let mut s = session();
    let cases = [
        ("0x1 / 0x0", "INVALID_ARGUMENT"),
        ("0x1 % 0x0", "INVALID_ARGUMENT"),
        ("0x1 +", "INVALID_ARGUMENT"),
        ("(0x1", "INVALID_ARGUMENT"),
        ("0x1)", "INVALID_ARGUMENT"),
        ("", "INVALID_ARGUMENT"),
        ("   ", "INVALID_ARGUMENT"),
        ("0x1 < 0x2", "INVALID_ARGUMENT"),
        ("0x1 0x2", "INVALID_ARGUMENT"),
        ("()", "INVALID_ARGUMENT"),
        ("0xzz", "ADDRESS_INVALID"),
        ("0x10000000000000000", "ADDRESS_INVALID"),
        ("main", "NO_BINARY_OPEN"),
    ];
    for (expr, want) in cases {
        let envelope = calc(&mut s, expr);
        assert_eq!(code(&envelope), want, "{expr}: {envelope}");
    }
    let envelope = calc(&mut s, "0x10 + 16");
    assert_eq!(code(&envelope), "ADDRESS_BASE_AMBIGUOUS", "{envelope}");
    let values: Vec<String> = envelope
        .pointer("/error/candidates")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|c| text_at(c, "/value"))
        .collect();
    assert_eq!(values, ["0x10 + 0x10", "0x10 + 0x16"]);
    let envelope = calc(&mut s, "99999999999999999999");
    assert_eq!(code(&envelope), "ADDRESS_BASE_AMBIGUOUS", "{envelope}");
    let envelope = call(&mut s, "calc", r#"{"expr":7}"#);
    assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{envelope}");
}

#[test]
fn calc_names_on_demo() {
    let mut s = demo();
    let main = format!("{DEMO_MAIN:#x}");
    for (expr, want) in [
        ("main", DEMO_MAIN),
        ("main+0x10", DEMO_MAIN + 0x10),
        ("main + 0x10", DEMO_MAIN + 0x10),
        (".text", 0x1080),
        ("sec:16:.text", 0x1080),
        ("seg:3", 0x1000),
        ("file:0x1084", 0x1084),
        ("check_password - main", 0x11e0 - DEMO_MAIN),
        ("FUN_00001234", 0x1234),
        ("main@0x1080", DEMO_MAIN),
        ("(main & ~0xff) >> 0x4", (DEMO_MAIN & !0xff) >> 4),
    ] {
        let envelope = calc(&mut s, expr);
        assert_eq!(
            text_at(data(&envelope), "/value"),
            format!("{want:#x}"),
            "{expr}"
        );
    }
    let envelope = calc(&mut s, "main");
    let got = data(&envelope);
    assert_eq!(got.pointer("/address/mapped"), Some(&Value::Bool(true)));
    assert_eq!(text_at(got, "/address/file_offset"), main);
    assert_eq!(got.pointer("/address/func"), Some(&Value::Null));
    assert!(!text_at(got, "/address/region").is_empty(), "{got}");
    handlers::calc::SPEC
        .output
        .check(got, Fit::Exact)
        .unwrap_or_else(|e| panic!("{e}"));

    add_function(&mut s, crate::support::DEMO_ID, DEMO_MAIN, 0x53);
    let envelope = calc(&mut s, "main+0x10");
    let got = data(&envelope);
    assert_eq!(text_at(got, "/address/func/id"), format!("fn:{main}"));
    assert_eq!(text_at(got, "/address/func/name/text"), "main");
    let envelope = calc(&mut s, "fn:0x1080+0x4");
    assert_eq!(text_at(data(&envelope), "/value"), "0x1084");

    let envelope = calc(&mut s, "0x10");
    let got = data(&envelope);
    assert_eq!(got.pointer("/address/mapped"), Some(&Value::Bool(false)));
    assert_eq!(got.pointer("/address/region"), Some(&Value::Null));
    assert_eq!(got.pointer("/address/file_offset"), Some(&Value::Null));

    let envelope = calc(&mut s, "no_such_name + 0x1");
    assert_eq!(code(&envelope), "NOT_FOUND", "{envelope}");
    let envelope = calc(&mut s, "note:3");
    assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{envelope}");
}
