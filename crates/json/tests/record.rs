//! Record codec contract: `json_record!`, `ToJson`, `FromJson` and the errors of a read.

#![allow(clippy::panic, reason = "a test fails through a panic")]

mod common;

use std::collections::BTreeMap;

use ghidorah_json::{
    DecodeError, DecodeKind, Fields, FromJson, ToJson, Value, field_key, json_record, parse,
};
use ghidorah_testkit::pbt;

json_record! {
    /// One call site.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Call {
        /// The target name.
        pub to: String,
        /// The argument count, or `None`.
        pub args: Option<u8>,
    }

    /// A function record with every supported field type.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Func {
        /// The entry point.
        pub addr: u64,
        /// The name.
        pub name: String,
        /// A raw identifier field: the member name is `type`.
        pub r#type: String,
        /// The stack delta.
        pub delta: i32,
        /// Whether the function returns.
        pub returns: bool,
        /// The call sites.
        pub calls: Vec<Call>,
        /// Tags by name.
        pub tags: BTreeMap<String, u16>,
        /// A free value.
        pub extra: Value,
        /// A boxed record.
        pub first: Option<Box<Call>>,
    }

    /// A record with no fields.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub struct Empty {}
}

fn sample() -> Func {
    Func {
        addr: 0x40_1000,
        name: "main".to_owned(),
        r#type: "int (void)".to_owned(),
        delta: -8,
        returns: true,
        calls: vec![
            Call {
                to: "puts".to_owned(),
                args: Some(1),
            },
            Call {
                to: "exit".to_owned(),
                args: None,
            },
        ],
        tags: BTreeMap::from([("hot".to_owned(), 2), ("entry".to_owned(), 1)]),
        extra: Value::Array(vec![Value::Null]),
        first: Some(Box::new(Call {
            to: "init".to_owned(),
            args: None,
        })),
    }
}

fn decode(text: &str) -> Result<Func, (DecodeKind, String)> {
    let value = parse(text, &common::limits()).unwrap_or_else(|e| panic!("{text}: {e}"));
    Func::from_json(&value).map_err(|e| (e.kind(), e.path()))
}

#[test]
fn json_record_roundtrip() {
    let func = sample();
    let value = func.to_json();
    assert_eq!(
        value.to_string(),
        concat!(
            r#"{"addr":4198400,"name":"main","type":"int (void)","delta":-8,"returns":true,"#,
            r#""calls":[{"to":"puts","args":1},{"to":"exit"}],"tags":{"entry":1,"hot":2},"#,
            r#""extra":[null],"first":{"to":"init"}}"#
        )
    );
    assert_eq!(Func::from_json(&value).as_ref(), Ok(&func));
    assert_eq!(Empty::default().to_json().to_string(), "{}");
    assert_eq!(
        Empty::from_json(&Value::object(Vec::<(String, Value)>::new())),
        Ok(Empty {})
    );
    // A null optional field reads as `None`.
    let call =
        Call::from_json(&parse(r#"{"to":"x","args":null}"#, &common::limits()).unwrap_or_default());
    assert_eq!(
        call,
        Ok(Call {
            to: "x".to_owned(),
            args: None
        })
    );
    pbt::check("json_record_roundtrip", 300, |g| {
        let call = Call {
            to: common::string(g),
            args: if g.bool() { Some(g.u8()) } else { None },
        };
        let back = Call::from_json(&call.to_json()).map_err(|e| e.to_string())?;
        if back == call {
            Ok(())
        } else {
            Err(format!("{call:?} gives {back:?}"))
        }
    });
}

#[test]
fn json_record_errors() {
    let base = r#""addr":1,"name":"n","type":"t","delta":0,"returns":false,"calls":[],"tags":{},"extra":null"#;
    assert!(decode(&format!("{{{base}}}")).is_ok());
    let cases = [
        (r#"{"addr":1}"#.to_owned(), DecodeKind::Missing, "/name"),
        (
            format!(r#"{{{base},"more":1}}"#),
            DecodeKind::Unknown,
            "/more",
        ),
        (
            format!(r#"{{{base},"addr":2}}"#),
            DecodeKind::Duplicate,
            "/addr",
        ),
    ];
    for (text, kind, path) in &cases {
        assert_eq!(decode(text), Err((*kind, (*path).to_owned())), "{text}");
    }
    let bad_addr = format!("{{{}}}", base.replace(r#""addr":1"#, r#""addr":-1"#));
    assert_eq!(
        decode(&bad_addr),
        Err((DecodeKind::Range, "/addr".to_owned()))
    );
    let float_addr = format!("{{{}}}", base.replace(r#""addr":1"#, r#""addr":1.5"#));
    assert_eq!(
        decode(&float_addr),
        Err((DecodeKind::Range, "/addr".to_owned()))
    );
    let big_delta = format!(
        "{{{}}}",
        base.replace(r#""delta":0"#, r#""delta":2147483648"#)
    );
    assert_eq!(
        decode(&big_delta),
        Err((DecodeKind::Range, "/delta".to_owned()))
    );
    let bad_call = format!(
        "{{{}}}",
        base.replace(r#""calls":[]"#, r#""calls":[{"to":"a"},{"to":7}]"#)
    );
    assert_eq!(
        decode(&bad_call),
        Err((
            DecodeKind::Type {
                expected: "string",
                found: "number"
            },
            "/calls/1/to".to_owned()
        ))
    );
    let bad_tag = format!(
        "{{{}}}",
        base.replace(r#""tags":{}"#, r#""tags":{"a/b":true}"#)
    );
    assert_eq!(
        decode(&bad_tag),
        Err((
            DecodeKind::Type {
                expected: "unsigned integer",
                found: "bool"
            },
            "/tags/a~1b".to_owned()
        ))
    );
    let dup_tag = format!(
        "{{{}}}",
        base.replace(r#""tags":{}"#, r#""tags":{"a":1,"a":2}"#)
    );
    assert_eq!(
        decode(&dup_tag),
        Err((DecodeKind::Duplicate, "/tags/a".to_owned()))
    );
    assert_eq!(
        decode("[1]"),
        Err((
            DecodeKind::Type {
                expected: "object",
                found: "array"
            },
            String::new()
        ))
    );
}

#[test]
fn decode_error_texts() {
    let err = DecodeError::new(DecodeKind::Missing)
        .at_key("x")
        .at_index(2)
        .at_key("items");
    assert_eq!(err.path(), "/items/2/x");
    assert_eq!(
        err.to_string(),
        "E_MISSING at '/items/2/x': the required field is missing"
    );
    assert_eq!(DecodeKind::Range.as_str(), "E_RANGE");
    let texts: Vec<String> = [
        DecodeKind::Range,
        DecodeKind::Unknown,
        DecodeKind::Duplicate,
    ]
    .into_iter()
    .map(|kind| DecodeError::new(kind).at_key("k").to_string())
    .collect();
    assert_eq!(
        texts,
        [
            "E_RANGE at '/k': the number is not an integer in range",
            "E_UNKNOWN at '/k': the record has no field with this name",
            "E_DUPLICATE at '/k': the object has two members with this name",
        ]
    );
    assert_eq!(
        DecodeError::new(DecodeKind::Unknown).kind(),
        DecodeKind::Unknown
    );
}

#[test]
fn std_codecs() {
    assert_eq!(field_key("r#type"), "type");
    assert_eq!(field_key("name"), "name");
    assert_eq!(true.to_json(), Value::Bool(true));
    assert_eq!(bool::from_json(&Value::Bool(false)), Ok(false));
    assert_eq!(u8::from_json(&Value::from(255u16)), Ok(255));
    assert_eq!(
        u8::from_json(&Value::from(256u16)).map_err(|e| e.kind()),
        Err(DecodeKind::Range)
    );
    assert_eq!(i8::from_json(&Value::from(-128i16)), Ok(-128));
    assert_eq!(u64::MAX.to_json().to_string(), "18446744073709551615");
    assert_eq!(i64::MIN.to_json().to_string(), "-9223372036854775808");
    assert_eq!(usize::from_json(&Value::from(7u8)), Ok(7));
    assert_eq!(isize::from_json(&Value::from(-7i8)), Ok(-7));
    assert_eq!(String::from_json(&Value::from("s")), Ok("s".to_owned()));
    assert_eq!(
        Vec::<u8>::from_json(&parse("[1,2]", &common::limits()).unwrap_or_default()),
        Ok(vec![1, 2])
    );
    assert_eq!(Option::<u8>::from_json(&Value::Null), Ok(None));
    assert_eq!(Option::<u8>::from_json(&Value::from(3u8)), Ok(Some(3)));
    assert_eq!(Option::<u8>::from_absent(), Some(None));
    assert_eq!(u8::from_absent(), None);
    assert!(None::<u8>.is_absent());
    assert!(!Some(1u8).is_absent());
    assert_eq!(Some(1u8).to_json(), Value::from(1u8));
    assert_eq!(None::<u8>.to_json(), Value::Null);
    let value = Value::object([("k", Value::from(1u8))]);
    assert_eq!(Value::from_json(&value).as_ref(), Ok(&value));
    assert_eq!(value.to_json(), value);
    assert_eq!(Box::new(5u32).to_json(), Value::from(5u32));
    let fields = Fields::new(&value, &["k", "z"]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(fields.take::<u8>("k"), Ok(1));
    assert_eq!(fields.take::<Option<u8>>("z"), Ok(None));
    assert_eq!(
        fields.take::<u8>("z").map_err(|e| (e.kind(), e.path())),
        Err((DecodeKind::Missing, "/z".to_owned()))
    );
    let wrong = Fields::new(&Value::from(1u8), &[]).map(|_| ());
    assert_eq!(
        wrong.map_err(|e| e.to_string()),
        Err("E_TYPE at '': expected object, found number".to_owned())
    );
}
