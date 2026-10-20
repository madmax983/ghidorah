//! Error objects, unknown arguments and selector rules (AC-134, AC-140, AC-142, AC-221).

use std::path::PathBuf;

use ghidorah_base::{ErrorCode, FixedClock, WarningCode};
use ghidorah_json::Value;
use ghidorah_tools::args::parse_strict;
use ghidorah_tools::errors::{ERROR_CAP, MAX_CANDIDATES, cut};
use ghidorah_tools::{
    Args, Call, Candidate, Ctx, Example, Payload, Registry, Request, ToolError, ToolSpec,
    dispatch_with,
};

use ghidorah_tools::{Host, Roots, Session, SessionConfig};

use crate::common::{chars, code, json, root, run, run_on, text, walk};
use crate::test_registry::{ITEM_EDIT, TestHost, registry};

/// The texts that no error or warning may hold (AC-142).
const DEBUG_MARKS: [&str; 4] = ["Some(", "Os {", "Error {", "panicked at"];

fn huge_error(code: ErrorCode) -> ToolError {
    let long = "k".repeat(20_000);
    let candidates = (0..100)
        .map(|i| Candidate::text(&format!("{i}{}", "v".repeat(1_000)), &"l".repeat(1_000)))
        .collect();
    ToolError::new(code)
        .var("field", &long)
        .var("tool", &long)
        .var("kind", &long)
        .path(&"/p".repeat(2_000))
        .detail("blob", Value::from("d".repeat(20_000)))
        .candidates(candidates)
}

fn boom(_: &mut TestHost, _: &Args, _: &mut Ctx) -> Result<Payload, ToolError> {
    panic!("Some(1) Error {{ panicked at the test }}");
}

fn big_error(_: &mut TestHost, _: &Args, _: &mut Ctx) -> Result<Payload, ToolError> {
    Err(huge_error(ErrorCode::AmbiguousName))
}

const BOOM: ToolSpec<TestHost> = ToolSpec {
    title: "Boom",
    summary: "Boom on each call.",
    description: "Boom on each call.",
    examples: &[Example {
        args: "{}",
        golden: "tests/golden/tools/test/none.json",
    }],
    binary: ghidorah_tools::BinaryArg::None,
    ..ToolSpec::base("boom", boom)
};

const BIG: ToolSpec<TestHost> = ToolSpec {
    title: "Big",
    summary: "Big error on each call.",
    description: "Big error on each call.",
    ..ToolSpec::base("big_error", big_error)
};

static FAULTY: &[&ToolSpec<TestHost>] = &[&BOOM, &BIG];

fn run_faulty(host: &mut TestHost, tool: &str) -> Value {
    dispatch_with(
        &Registry::new(FAULTY),
        host,
        &Request::new(tool, json("{}")),
    )
    .to_json()
}

#[test]
fn ac_134_error_cap() {
    for code in ErrorCode::ALL {
        let object = huge_error(code).to_json();
        let size = chars(&text(&object));
        assert!(size as u64 <= ERROR_CAP, "{code}: {size} characters");
        let candidates = object
            .get("candidates")
            .and_then(Value::as_array)
            .map_or(0, <[Value]>::len);
        assert!(candidates <= MAX_CANDIDATES);
        assert_eq!(
            object.get("candidates_total").and_then(Value::as_u64),
            Some(100)
        );
        assert_eq!(
            object.get("code").and_then(Value::as_str),
            Some(code.name())
        );
        assert_eq!(
            object.get("num").and_then(Value::as_u64),
            Some(u64::from(code.num()))
        );
    }
    let envelope = run_faulty(&mut TestHost::default(), "big_error");
    let error = envelope.get("error").expect("an error object");
    assert!(chars(&text(error)) as u64 <= ERROR_CAP);
    assert_eq!(
        error
            .get("candidates")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(5)
    );
    let long_key = format!("{{\"{}\":1}}", "q".repeat(5_000));
    let envelope = run("echo_value", &long_key);
    assert_eq!(code(&envelope), "UNKNOWN_ARGUMENT");
    assert!(chars(&text(envelope.get("error").expect("an error"))) as u64 <= ERROR_CAP);
    let small = ToolError::new(ErrorCode::NotFound)
        .candidates(vec![
            Candidate::text("a", "first"),
            Candidate::text("b", "second"),
        ])
        .to_json();
    assert_eq!(
        small.get("candidates_total").and_then(Value::as_u64),
        Some(2)
    );
    assert!(
        ToolError::new(ErrorCode::NotFound)
            .to_json()
            .get("candidates")
            .is_none()
    );
    assert_eq!(cut("abcdef", 3), "abc");
    assert_eq!(cut("äöü", 2), "äö");
}

#[test]
fn ac_140_unknown_argument() {
    let cases = [
        (
            "item_get",
            r#"{"targt":"0x401010"}"#,
            "/targt",
            r#"{"target":"0x401010"}"#,
        ),
        (
            "item_get",
            r#"{"target":"0x401010","zzzzzz":1}"#,
            "/zzzzzz",
            r#"{"target":"0x401010"}"#,
        ),
        (
            "item_get",
            r#"{"target":"0x401010","id":"0x401000"}"#,
            "/id",
            r#"{"target":"0x401010"}"#,
        ),
        (
            "item_list",
            r#"{"filter":{"nme":"func"}}"#,
            "/filter/nme",
            r#"{"filter":{"name":"func"}}"#,
        ),
        (
            "echo_value",
            r#"{"value":1,"fag":true}"#,
            "/fag",
            r#"{"value":1}"#,
        ),
        (
            "item_list",
            r#"{"limt":2,"sortt":"name"}"#,
            "/limt",
            r#"{"limit":2,"sort":"name"}"#,
        ),
    ];
    let registry = registry();
    for (tool, args, path, fixed) in cases {
        let envelope = run(tool, args);
        assert_eq!(
            code(&envelope),
            "UNKNOWN_ARGUMENT",
            "{tool} {args}: {envelope}"
        );
        assert_eq!(
            envelope
                .pointer("/error/field_path")
                .and_then(Value::as_str),
            Some(path)
        );
        let next = envelope.pointer("/next/0").expect("a repair call");
        assert_eq!(next.get("tool").and_then(Value::as_str), Some(tool));
        let next_args = next.get("args").expect("repair args");
        assert_eq!(next_args, &json(fixed), "{tool} {args}");
        let (_, spec) = registry.get(tool).expect("a test tool");
        parse_strict(spec, next_args).expect("the repair call passes validation");
        let again = run(tool, &text(next_args));
        assert_eq!(again.get("ok"), Some(&Value::Bool(true)), "{again}");
    }
    let envelope = run("item_get", r#"{"targt":"0x401010"}"#);
    assert_eq!(
        envelope
            .pointer("/error/candidates/0/value")
            .and_then(Value::as_str),
        Some("target")
    );
    assert_eq!(
        envelope.pointer("/error/retryable"),
        Some(&Value::Bool(false))
    );
}

#[test]
fn ac_221_selector_rules() {
    let rename_example = json(ITEM_EDIT.actions[1].example);
    let envelope = run("item_edit", r#"{"action":"rename","target":"0x401000"}"#);
    assert_eq!(code(&envelope), "MISSING_ARGUMENT", "{envelope}");
    assert_eq!(
        envelope
            .pointer("/error/details/action")
            .and_then(Value::as_str),
        Some("rename")
    );
    assert_eq!(
        envelope.pointer("/error/details/example"),
        Some(&rename_example)
    );
    assert_eq!(
        envelope
            .pointer("/error/field_path")
            .and_then(Value::as_str),
        Some("/name")
    );

    let envelope = run("item_edit", r#"{"action":"create","name":"x"}"#);
    assert_eq!(code(&envelope), "MISSING_ARGUMENT");
    assert_eq!(
        envelope
            .pointer("/error/details/action")
            .and_then(Value::as_str),
        Some("create")
    );
    assert_eq!(
        envelope
            .pointer("/error/field_path")
            .and_then(Value::as_str),
        Some("/target")
    );

    let envelope = run(
        "item_edit",
        r#"{"action":"delete","target":"0x401000","name":"x"}"#,
    );
    assert_eq!(code(&envelope), "INVALID_ARGUMENT");
    assert_eq!(
        envelope
            .pointer("/error/details/action")
            .and_then(Value::as_str),
        Some("delete")
    );
    assert_eq!(
        envelope
            .pointer("/error/details/forbidden")
            .and_then(Value::as_str),
        Some("name")
    );
    assert_eq!(
        envelope
            .pointer("/error/field_path")
            .and_then(Value::as_str),
        Some("/name")
    );

    let envelope = run("item_edit", r#"{"target":"0x401000"}"#);
    assert_eq!(code(&envelope), "MISSING_ARGUMENT");
    assert!(envelope.pointer("/error/details/example").is_some());
    assert!(envelope.pointer("/error/details/action").is_none());

    let envelope = run("item_edit", r#"{"action":"explode","target":"0x401000"}"#);
    assert_eq!(code(&envelope), "INVALID_ARGUMENT");
    let expected = envelope
        .pointer("/error/details/expected")
        .and_then(Value::as_str);
    assert!(expected.is_some_and(|e| e.contains("rename")), "{envelope}");

    for action in ITEM_EDIT.actions {
        let envelope = run("item_edit", action.example);
        assert_eq!(envelope.get("ok"), Some(&Value::Bool(true)), "{envelope}");
    }
}

/// Gives every text of the error object and the warnings of an envelope.
fn agent_texts(envelope: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for part in ["/error", "/warnings"] {
        if let Some(value) = envelope.pointer(part) {
            walk(value, "", &mut |_, _, v| {
                if let Some(t) = v.as_str() {
                    out.push(t.to_owned());
                }
            });
        }
    }
    out
}

#[test]
fn ac_142_no_debug_text() {
    let mut texts: Vec<String> = Vec::new();
    for code in ErrorCode::ALL {
        let error = ToolError::new(code)
            .var("field", "target")
            .var("tool", "x")
            .var("kind", "set");
        texts.push(error.message());
        texts.push(error.to_string());
        texts.push(error.hint(false));
        texts.extend(agent_texts(&Value::object([("error", error.to_json())])));
    }
    for code in WarningCode::ALL {
        texts.push(code.info().message.to_owned());
        texts.push(code.info().hint.to_owned());
    }
    let calls = [
        ("nope", "{}"),
        ("item_get", r#"{"targt":"0x401010"}"#),
        ("item_get", "{}"),
        ("item_get", r#"{"target":true}"#),
        ("item_get", r#"{"target":"0xZZ"}"#),
        ("item_get", r#"{"target":9007199254740993}"#),
        (
            "item_get",
            r#"{"targets":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51]}"#,
        ),
        (
            "item_get",
            r#"{"target":"0x401010","targets":["0x401000"]}"#,
        ),
        ("item_get", r#"{"target":"nosuch"}"#),
        ("item_get", r#"{"id":"0x401000"}"#),
        ("item_list", r#"{"count":"many"}"#),
        ("item_list", r#"{"count":30000}"#),
        ("item_list", r#"{"sort":"weight"}"#),
        ("item_list", r#"{"cursor":"bad"}"#),
        ("item_list", r#"{"in":"set:none"}"#),
        ("item_list", r#"{"fields":["no-slash"]}"#),
        (
            "item_edit",
            r#"{"action":"rename","target":"0x401000","name":"x","expected_rev":3}"#,
        ),
        ("echo_value", r#"{"value":1,"tag":"fn:0x1"}"#),
        ("echo_value", r#"{"value":1,"flag":"yes"}"#),
        ("echo_value", "[]"),
        ("fuel_run", r#"{"work":5000}"#),
    ];
    for (tool, args) in calls {
        let envelope = run(tool, args);
        assert!(envelope.get("ok").is_some(), "{tool} {args}");
        texts.extend(agent_texts(&envelope));
    }
    let mut host = TestHost::default();
    let envelope = run_faulty(&mut host, "boom");
    assert_eq!(code(&envelope), "INTERNAL_ERROR");
    assert!(
        envelope
            .pointer("/error/crash_id")
            .and_then(Value::as_str)
            .is_some()
    );
    texts.extend(agent_texts(&envelope));
    host.binaries.clear();
    texts.extend(agent_texts(
        &run_on(&mut host, "item_get", r#"{"target":"0x401000"}"#).to_json(),
    ));
    assert!(texts.len() > 100);
    for t in &texts {
        for mark in DEBUG_MARKS {
            assert!(!t.contains(mark), "debug text {mark:?} in {t:?}");
        }
    }
    let call = Call::new(
        "item_get",
        json(r#"{"target":"0x401000"}"#),
        "Read the item.",
    );
    assert_eq!(
        call.to_json().get("why").and_then(Value::as_str),
        Some("Read the item.")
    );
}

/// An `expected_rev` that differs gives `CONFLICT` with a history read in `next[0]`. The call
/// with the current rev is only a candidate, so a client that sends `next[0]` never writes
/// over edits that it did not read.
#[test]
fn regress_conflict_next_reads_history() {
    let roots = Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid");
    let mut s = Session::with_registry(
        <Session as Host>::registry(),
        SessionConfig::new(roots),
        Box::new(FixedClock::new(0)),
    );
    let registry = s.active_registry();
    let mut send = |tool: &str, args: &str| {
        dispatch_with(&registry, &mut s, &Request::new(tool, json(args))).to_json()
    };
    assert_eq!(code(&send("binary_load", r#"{"builtin":"demo"}"#)), "");
    for _ in 0..2 {
        assert_eq!(
            code(&send("note_write", r#"{"kind":"note","text":"x"}"#)),
            ""
        );
    }
    let args = r#"{"target":"0x1090","name":"read_input","expected_rev":1}"#;
    let conflict = send("symbol_rename", args);
    assert_eq!(code(&conflict), "CONFLICT", "{conflict}");
    assert_eq!(
        conflict.pointer("/error/details/current_rev"),
        Some(&json("2"))
    );
    assert_eq!(
        conflict.pointer("/next/0/tool").and_then(Value::as_str),
        Some("history_list"),
        "{conflict}"
    );
    assert_eq!(
        conflict.pointer("/next/0/args"),
        Some(&json(r#"{"since_rev":1}"#)),
        "{conflict}"
    );
    let next = conflict.pointer("/next").and_then(Value::as_array);
    let resend = next
        .unwrap_or_default()
        .iter()
        .any(|c| c.get("tool").and_then(Value::as_str) == Some("symbol_rename"));
    assert!(!resend, "the resend is not in next: {conflict}");
    let value = conflict.pointer("/error/candidates/0/value");
    let wants = [
        ("target", r#""0x1090""#),
        ("name", r#""read_input""#),
        ("expected_rev", "2"),
    ];
    for (key, want) in wants {
        assert_eq!(
            value.and_then(|v| v.get(key)),
            Some(&json(want)),
            "{key}: {conflict}"
        );
    }
    assert_eq!(
        ErrorCode::Conflict.info().class,
        ghidorah_base::RepairClass::Helper
    );
}

/// The `UNKNOWN_ARGUMENT` repair wraps a scalar for a list argument. A repair that still fails
/// the strict parser gives the `tool_search` helper call (agent-protocol-06).
#[test]
fn regress_unknown_argument_repair_wraps_list() {
    let roots = Roots::new(&root(), &[PathBuf::from(".")]).expect("the root is valid");
    let mut s = Session::with_registry(
        <Session as Host>::registry(),
        SessionConfig::new(roots),
        Box::new(FixedClock::new(0)),
    );
    let registry = s.active_registry();
    let mut send = |tool: &str, args: &str| {
        dispatch_with(&registry, &mut s, &Request::new(tool, json(args))).to_json()
    };
    assert_eq!(code(&send("binary_load", r#"{"builtin":"demo"}"#)), "");
    let wrapped = send("xref_list", r#"{"target":"main"}"#);
    assert_eq!(code(&wrapped), "UNKNOWN_ARGUMENT", "{wrapped}");
    assert_eq!(
        wrapped.pointer("/next/0/tool").and_then(Value::as_str),
        Some("xref_list"),
        "{wrapped}"
    );
    let args = wrapped
        .pointer("/next/0/args")
        .cloned()
        .expect("repair args");
    assert_eq!(args, json(r#"{"targets":["main"]}"#), "{wrapped}");
    let again = send("xref_list", &text(&args));
    assert_eq!(code(&again), "", "{again}");

    let helper = send("func_get", r#"{"func":"main"}"#);
    assert_eq!(code(&helper), "UNKNOWN_ARGUMENT", "{helper}");
    assert_eq!(
        helper.pointer("/next/0/tool").and_then(Value::as_str),
        Some("tool_search"),
        "{helper}"
    );
    assert_eq!(
        helper.pointer("/next/0/args"),
        Some(&json(r#"{"name":"func_get","level":"full"}"#)),
        "{helper}"
    );
    let step = r#"{"steps":[{"id":"a","tool":"func_get","args":{"func":"main"}}]}"#;
    let batch = send("batch_run", step);
    assert_eq!(code(&batch), "UNKNOWN_ARGUMENT", "{batch}");
    assert_eq!(
        batch.pointer("/next/0/args"),
        Some(&json(r#"{"name":"func_get","level":"full"}"#)),
        "{batch}"
    );
    for envelope in [&wrapped, &helper] {
        let message = envelope
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(!message.contains("next[0]"), "{envelope}");
        let hint = envelope
            .pointer("/error/hint")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(hint.contains("next[0]"), "{envelope}");
    }
}
