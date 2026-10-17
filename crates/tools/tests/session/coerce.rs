//! Lenient coercion (AC-139).

use ghidorah_json::{Object, Value};
use ghidorah_tools::coerce::lenient;
use ghidorah_tools::{
    ArgKind, ArgSpec, Args, BinaryArg, Ctx, Example, Payload, Registry, Role, Session, ToolError,
    ToolSpec,
};

use crate::support::{WP13B, call, code, config, data, json};

const FILTER: &[ArgSpec] = &[
    ArgSpec::new("name", Role::Param, ArgKind::Str(64), "A name part."),
    ArgSpec::new(
        "size_min",
        Role::Param,
        ArgKind::Int { min: 0, max: 1_000 },
        "The smallest size.",
    ),
];
const WORD: ArgSpec = ArgSpec::new("word", Role::Param, ArgKind::Str(16), "One word.");

const ARGS: &[ArgSpec] = &[
    ArgSpec::new(
        "targets",
        Role::Targets,
        ArgKind::AddrList(50),
        "The addresses.",
    ),
    ArgSpec::new("filter", Role::Param, ArgKind::Obj(FILTER), "A filter."),
    ArgSpec::new("words", Role::Param, ArgKind::List(&WORD, 8), "The words."),
    ArgSpec::new(
        "count",
        Role::Param,
        ArgKind::Int {
            min: -10,
            max: 1_000,
        },
        "A count.",
    ),
    ArgSpec::new("flag", Role::Param, ArgKind::Bool, "A flag."),
    ArgSpec::new(
        "sort",
        Role::Param,
        ArgKind::Enum(&["addr", "name"]),
        "The sort order.",
    ),
];

fn echo(_s: &mut Session, args: &Args, _ctx: &mut Ctx) -> Result<Payload, ToolError> {
    Ok(Payload::Object(
        args.values()
            .map(|(name, value)| (name, value.clone()))
            .collect::<Object>(),
    ))
}

/// A test tool with one argument of each kind that coerces.
const ECHO: ToolSpec<Session> = ToolSpec {
    title: "Echo",
    summary: "Echo the arguments.",
    description: "Echo the arguments.",
    args: ARGS,
    examples: &[Example {
        args: "{}",
        golden: "tests/golden/tools/echo.json",
    }],
    binary: BinaryArg::None,
    ..ToolSpec::base("echo_args", echo)
};

/// `(argument, native JSON, stringified JSON)`.
const MATRIX: [(&str, &str, &str); 9] = [
    ("targets", r#"["0x10","main"]"#, r#""[\"0x10\",\"main\"]""#),
    (
        "filter",
        r#"{"name":"a","size_min":3}"#,
        r#""{\"name\":\"a\",\"size_min\":3}""#,
    ),
    ("words", r#"["a","b"]"#, r#""[\"a\",\"b\"]""#),
    ("count", "42", r#""42""#),
    ("count", "-7", r#""-7""#),
    ("flag", "true", r#""true""#),
    ("flag", "false", r#""FALSE""#),
    ("sort", r#""name""#, r#""NAME""#),
    ("sort", r#""addr""#, r#""Addr""#),
];

fn echo_session() -> Session {
    let mut tools: Vec<&'static ToolSpec<Session>> = WP13B.to_vec();
    tools.push(&ECHO);
    Session::with_registry(
        Registry::new(Box::leak(tools.into_boxed_slice())),
        config(),
        Box::new(ghidorah_base::FixedClock::new(0)),
    )
}

#[test]
fn ac_139_coercion_matrix() {
    let mut s = echo_session();
    for (name, native, text) in MATRIX {
        let plain = call(&mut s, "echo_args", &format!(r#"{{"{name}":{native}}}"#));
        let coerced = call(&mut s, "echo_args", &format!(r#"{{"{name}":{text}}}"#));
        assert_eq!(data(&plain), data(&coerced), "{name}: {text}");
        assert!(plain.get("warnings").is_none(), "{plain}");
        let warning = coerced.pointer("/warnings/0").expect("a warning");
        assert_eq!(
            warning.get("code"),
            Some(&Value::from("W_COERCED")),
            "{coerced}"
        );
        assert_eq!(warning.get("field"), Some(&Value::from(format!("/{name}"))));
    }
    // The detailed format names the two types.
    let detailed = call(&mut s, "echo_args", r#"{"count":"5","format":"detailed"}"#);
    assert_eq!(
        detailed.pointer("/warnings/0/details/from_type"),
        Some(&Value::from("string"))
    );
    // Global arguments coerce too.
    let paged = call(&mut s, "tool_search", r#"{"limit":"1","level":"NAMES"}"#);
    assert_eq!(
        paged.pointer("/page/returned"),
        Some(&Value::from(1_u64)),
        "{paged}"
    );
    assert_eq!(
        paged.pointer("/warnings/1/code"),
        Some(&Value::from("W_COERCED"))
    );
    // A tool of WP-13b gives the same data for a coerced value.
    let a = call(
        &mut s,
        "binary_load",
        r#"{"builtin":"demo","analysis":"none"}"#,
    );
    let b = call(
        &mut s,
        "binary_load",
        r#"{"builtin":"DEMO","analysis":"None"}"#,
    );
    assert_eq!(data(&a).get("binary_id"), data(&b).get("binary_id"));
    assert_eq!(
        b.pointer("/warnings/0/code"),
        Some(&Value::from("W_COERCED"))
    );
    // Text that does not coerce keeps its error.
    for (args, want) in [
        (r#"{"count":"0x10"}"#, "INVALID_ARGUMENT"),
        (r#"{"count":"4.5"}"#, "INVALID_ARGUMENT"),
        (r#"{"count":"5000"}"#, "INVALID_ARGUMENT"),
        (r#"{"flag":"yes"}"#, "INVALID_ARGUMENT"),
        (r#"{"sort":"size"}"#, "INVALID_ARGUMENT"),
        (r#"{"targets":"[1,"}"#, "INVALID_ARGUMENT"),
        (r#"{"targets":"{}"}"#, "INVALID_ARGUMENT"),
        (r#"{"filter":"[]"}"#, "INVALID_ARGUMENT"),
        (r#"{"filter":"{\"nope\":1}"}"#, "INVALID_ARGUMENT"),
    ] {
        let envelope = call(&mut s, "echo_args", args);
        assert_eq!(code(&envelope), want, "{args}: {envelope}");
    }
}

#[test]
fn coerce_table() {
    let int = ArgKind::Int { min: 0, max: 9 };
    let cases: [(ArgKind, &str, Option<&str>); 12] = [
        (int, r#""7""#, Some("7")),
        (int, r#"" 7""#, None),
        (int, r#""+7""#, None),
        (int, r#""""#, None),
        (int, "7.5", None),
        (ArgKind::Bool, r#""True""#, Some("true")),
        (ArgKind::Bool, "1", None),
        (ArgKind::Enum(&["a", "b"]), r#""B""#, Some(r#""b""#)),
        (ArgKind::Enum(&["a", "b"]), r#""c""#, None),
        (ArgKind::AddrList(4), r#""[1,2]""#, Some("[1,2]")),
        (ArgKind::Obj(&[]), r#""{}""#, Some("{}")),
        (ArgKind::Str(4), "7", None),
    ];
    for (kind, input, want) in cases {
        let got = lenient(&kind, &json(input));
        assert_eq!(got, want.map(json), "{input}");
    }
}
