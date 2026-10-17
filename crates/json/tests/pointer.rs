//! Pointer contract: RFC 6901 plus the `*` segment.

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod common;

use ghidorah_json::pointer::{self, Pointer, PointerError, Segment, Selection};
use ghidorah_json::{Value, parse};

fn doc(text: &str) -> Value {
    parse(text, &common::limits()).unwrap_or_else(|e| panic!("{text}: {e}"))
}

fn ptr(text: &str) -> Pointer {
    pointer::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

fn texts(selection: &Selection<'_>) -> Vec<String> {
    selection.values.iter().map(ToString::to_string).collect()
}

/// The example document of RFC 6901 Section 5.
const RFC_DOC: &str = r#"{
    "foo": ["bar", "baz"],
    "": 0,
    "a/b": 1,
    "c%d": 2,
    "e^f": 3,
    "g|h": 4,
    "i\\j": 5,
    "k\"l": 6,
    " ": 7,
    "m~n": 8
}"#;

#[test]
fn pointer_rfc6901_examples() {
    let value = doc(RFC_DOC);
    let cases: &[(&str, &str)] = &[
        ("/foo", r#"["bar","baz"]"#),
        ("/foo/0", r#""bar""#),
        ("/", "0"),
        ("/a~1b", "1"),
        ("/c%d", "2"),
        ("/e^f", "3"),
        ("/g|h", "4"),
        ("/i\\j", "5"),
        ("/k\"l", "6"),
        ("/ ", "7"),
        ("/m~0n", "8"),
    ];
    assert_eq!(pointer::get(&value, &ptr("")), Some(&value));
    for &(text, expected) in cases {
        let got = pointer::get(&value, &ptr(text)).map(Value::to_string);
        assert_eq!(got.as_deref(), Some(expected), "{text}");
        assert_eq!(
            value.pointer(text).map(Value::to_string).as_deref(),
            Some(expected)
        );
        let selection = pointer::select(&value, &ptr(text));
        assert_eq!(texts(&selection), [expected], "{text}");
        assert!(selection.is_complete());
    }
}

#[test]
fn pointer_parse_table() {
    let ok: &[(&str, &[Segment])] = &[
        ("", &[]),
        ("/", &[Segment::Key(String::new())]),
        (
            "//",
            &[Segment::Key(String::new()), Segment::Key(String::new())],
        ),
        (
            "/a~1b/~0",
            &[Segment::Key("a/b".to_owned()), Segment::Key("~".to_owned())],
        ),
        ("/~01", &[Segment::Key("~1".to_owned())]),
        ("/*", &[Segment::Star]),
        ("/**", &[Segment::Key("**".to_owned())]),
        (
            "/a/*/b",
            &[
                Segment::Key("a".to_owned()),
                Segment::Star,
                Segment::Key("b".to_owned()),
            ],
        ),
    ];
    for &(text, segments) in ok {
        let parsed = ptr(text);
        assert_eq!(parsed.segments(), segments, "{text:?}");
        assert_eq!(parsed.to_string(), text, "display of {text:?}");
        assert_eq!(text.parse::<Pointer>().as_ref(), Ok(&parsed));
        assert_eq!(parsed.has_star(), segments.contains(&Segment::Star));
    }
    let bad: &[(&str, PointerError)] = &[
        ("a", PointerError::NoLeadingSlash),
        ("#/a", PointerError::NoLeadingSlash),
        ("/~", PointerError::BadEscape { offset: 1 }),
        ("/a~2", PointerError::BadEscape { offset: 2 }),
        ("/ok/x~", PointerError::BadEscape { offset: 5 }),
    ];
    for &(text, error) in bad {
        assert_eq!(pointer::parse(text), Err(error), "{text:?}");
        assert_eq!(Value::Null.pointer(text), None);
    }
    assert_eq!(PointerError::NoLeadingSlash.code(), "E_POINTER_SLASH");
    assert_eq!(
        PointerError::NoLeadingSlash.to_string(),
        "E_POINTER_SLASH: a pointer that is not empty starts with '/'"
    );
    assert_eq!(
        PointerError::BadEscape { offset: 3 }.to_string(),
        "E_POINTER_ESCAPE at byte 3: '~' must come before '0' or '1'"
    );
    let mut built = Pointer::root();
    built.push(Segment::Key("a/b".to_owned()));
    built.push(Segment::Star);
    assert_eq!(built.to_string(), "/a~1b/*");
    assert_eq!(
        Pointer::from_segments(vec![Segment::Star]).segments()[0].token(),
        "*"
    );
}

#[test]
fn pointer_array_indexes() {
    let value = doc(r#"{"a":[10,20,30],"01":"key"}"#);
    let get = |text: &str| pointer::get(&value, &ptr(text)).map(Value::to_string);
    assert_eq!(get("/a/0").as_deref(), Some("10"));
    assert_eq!(get("/a/2").as_deref(), Some("30"));
    assert_eq!(get("/a/3"), None);
    assert_eq!(get("/a/01"), None, "a leading zero is not an index");
    assert_eq!(
        get("/a/-"),
        None,
        "the index after the last item has no value"
    );
    assert_eq!(get("/a/+1"), None);
    assert_eq!(get("/a/18446744073709551616"), None);
    assert_eq!(
        get("/01").as_deref(),
        Some(r#""key""#),
        "on an object it is a name"
    );
    assert_eq!(get("/a/0/x"), None, "a scalar has no members");
}

#[test]
fn pointer_star_maps_arrays() {
    let value = doc(r#"{"data":{"items":[
            {"id":"fn:1","calls":[{"to":"a"},{"to":"b"}]},
            {"id":"fn:2","calls":[]},
            {"id":"fn:3","calls":[{"to":"c"}]}
        ]},"*":"star member"}"#);
    let ids = pointer::select(&value, &ptr("/data/items/*/id"));
    assert_eq!(texts(&ids), [r#""fn:1""#, r#""fn:2""#, r#""fn:3""#]);
    assert!(ids.is_complete());
    let nested = pointer::select(&value, &ptr("/data/items/*/calls/*/to"));
    assert_eq!(texts(&nested), [r#""a""#, r#""b""#, r#""c""#]);
    let whole = pointer::select(&value, &ptr("/data/items/*"));
    assert_eq!(whole.values.len(), 3);
    let on_object = pointer::select(&value, &ptr("/*"));
    assert_eq!(
        texts(&on_object),
        [r#""star member""#],
        "on an object it is the name *"
    );
    assert_eq!(
        pointer::get(&value, &ptr("/data/items/*")),
        None,
        "get keeps RFC 6901"
    );
    assert_eq!(
        pointer::get(&value, &ptr("/*"))
            .map(Value::to_string)
            .as_deref(),
        Some(r#""star member""#)
    );
}

#[test]
fn pointer_star_on_empty_array() {
    let value = doc(r#"{"items":[],"rows":[[],[1],[]]}"#);
    for text in ["/items/*", "/items/*/id", "/items/*/*"] {
        let selection = pointer::select(&value, &ptr(text));
        assert_eq!(selection, Selection::default(), "{text}");
        assert!(selection.is_complete());
    }
    let rows = pointer::select(&value, &ptr("/rows/*/*"));
    assert_eq!(texts(&rows), ["1"]);
    assert!(rows.is_complete());
}

#[test]
fn pointer_select_counts_missing() {
    let value = doc(r#"{"items":[{"id":1},{"name":"x"},{"id":3},5,{"name":"y"}]}"#);
    let selection = pointer::select(&value, &ptr("/items/*/id"));
    assert_eq!(texts(&selection), ["1", "3"]);
    assert_eq!(selection.missing, 3);
    assert_eq!(selection.first_missing.as_deref(), Some("/items/1/id"));
    assert!(!selection.is_complete());
    let none = pointer::select(&value, &ptr("/nothing/*"));
    assert_eq!(none.values.len(), 0);
    assert_eq!(none.missing, 1);
    assert_eq!(none.first_missing.as_deref(), Some("/nothing"));
    let one = Value::from(1u8);
    let scalar = pointer::select(&one, &ptr("/*"));
    assert_eq!(scalar.first_missing.as_deref(), Some("/*"));
    let slash = doc(r#"{"a/b":[{}]}"#);
    let escaped = pointer::select(&slash, &ptr("/a~1b/*/c~0d"));
    assert_eq!(escaped.first_missing.as_deref(), Some("/a~1b/0/c~0d"));
}
