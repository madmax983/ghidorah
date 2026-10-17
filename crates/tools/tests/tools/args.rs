//! The argument parser: kinds, caps, groups, defaults and globals.

use ghidorah_json::Value;
use ghidorah_tools::args::{Format, Shape, globals_of, parse, parse_strict};
use ghidorah_tools::{ArgKind, ToolSpec};

use crate::common::{json, text};
use crate::test_registry::{ECHO_VALUE, FUEL_RUN, ITEM_EDIT, ITEM_GET, ITEM_LIST, TestHost};

/// Gives the error code, the field path and the first repair args of a parse.
fn fail(tool: &ToolSpec<TestHost>, args: &str) -> (String, String, Option<Value>) {
    let error = parse(tool, &json(args), None).expect_err("the parse fails");
    (
        error.code.name().to_owned(),
        error.field_path.clone().unwrap_or_default(),
        error.next.first().map(|c| c.args.clone()),
    )
}

fn names(tool: &ToolSpec<TestHost>) -> Vec<&'static str> {
    globals_of(tool).iter().map(|g| g.name).collect()
}

#[test]
fn addresses_and_lists() {
    assert!(parse(&ITEM_GET, &json(r#"{"target":4198400}"#), None).is_ok());
    assert!(parse(&ITEM_GET, &json(r#"{"target":"main+0x10"}"#), None).is_ok());
    let (code, path, next) = fail(&ITEM_GET, r#"{"target":9007199254740993}"#);
    assert_eq!(
        (code.as_str(), path.as_str()),
        ("ADDRESS_INVALID", "/target")
    );
    assert_eq!(next, Some(json(r#"{"target":"0x20000000000001"}"#)));
    let (code, _, next) = fail(&ITEM_GET, r#"{"target":"0xZZ"}"#);
    assert_eq!((code.as_str(), next), ("ADDRESS_INVALID", None));
    assert_eq!(fail(&ITEM_GET, r#"{"target":-1}"#).0, "ADDRESS_INVALID");
    assert_eq!(fail(&ITEM_GET, r#"{"target":1.5}"#).0, "ADDRESS_INVALID");
    assert_eq!(fail(&ITEM_GET, r#"{"target":true}"#).0, "INVALID_ARGUMENT");
    let (code, path, _) = fail(&ITEM_GET, r#"{"targets":["0x1","0x2",false]}"#);
    assert_eq!(
        (code.as_str(), path.as_str()),
        ("INVALID_ARGUMENT", "/targets/2")
    );
    assert_eq!(
        fail(&ITEM_GET, r#"{"targets":"0x1"}"#).0,
        "INVALID_ARGUMENT"
    );
    let many: Vec<String> = (0..51)
        .map(|i| format!("\"{:#x}\"", 0x40_1000 + i * 16))
        .collect();
    let (code, path, next) = fail(&ITEM_GET, &format!(r#"{{"targets":[{}]}}"#, many.join(",")));
    assert_eq!(
        (code.as_str(), path.as_str()),
        ("LIMIT_EXCEEDED", "/targets")
    );
    let clamped = next.expect("a clamp");
    assert_eq!(
        clamped
            .get("targets")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(50)
    );
    let (code, path, next) = fail(
        &ITEM_GET,
        r#"{"target":"0x1","include":["summary","body","summary"]}"#,
    );
    assert_eq!(
        (code.as_str(), path.as_str()),
        ("LIMIT_EXCEEDED", "/include")
    );
    assert_eq!(
        next,
        Some(json(r#"{"target":"0x1","include":["summary","body"]}"#))
    );
    assert_eq!(
        fail(&ITEM_GET, r#"{"target":"0x1","include":"summary"}"#).0,
        "INVALID_ARGUMENT"
    );
    let (code, path, _) = fail(&ITEM_GET, r#"{"target":"0x1","include":["head"]}"#);
    assert_eq!(
        (code.as_str(), path.as_str()),
        ("INVALID_ARGUMENT", "/include/0")
    );
}

#[test]
fn scalars_and_objects() {
    let (code, path, next) = fail(&ITEM_LIST, r#"{"count":30000}"#);
    assert_eq!((code.as_str(), path.as_str()), ("LIMIT_EXCEEDED", "/count"));
    assert_eq!(next, Some(json(r#"{"count":20000}"#)));
    assert_eq!(fail(&ITEM_LIST, r#"{"count":-1}"#).0, "INVALID_ARGUMENT");
    assert_eq!(fail(&ITEM_LIST, r#"{"count":1.5}"#).0, "INVALID_ARGUMENT");
    assert_eq!(fail(&ITEM_LIST, r#"{"count":"5"}"#).0, "INVALID_ARGUMENT");
    let error = parse(&ITEM_LIST, &json(r#"{"sort":"nam"}"#), None).expect_err("a bad enum");
    assert_eq!(error.code.name(), "INVALID_ARGUMENT");
    assert_eq!(
        error.candidates.first().map(|c| text(&c.value)),
        Some("\"name\"".to_owned())
    );
    assert!(
        error
            .details
            .as_ref()
            .and_then(|d| d.get("expected"))
            .is_some()
    );
    assert_eq!(fail(&ITEM_LIST, r#"{"sort":3}"#).0, "INVALID_ARGUMENT");
    let (code, path, _) = fail(&ITEM_LIST, r#"{"filter":{"size_min":"big"}}"#);
    assert_eq!(
        (code.as_str(), path.as_str()),
        ("INVALID_ARGUMENT", "/filter/size_min")
    );
    assert_eq!(fail(&ITEM_LIST, r#"{"filter":[]}"#).0, "INVALID_ARGUMENT");
    let long = format!(r#"{{"filter":{{"name":"{}"}}}}"#, "n".repeat(70));
    let (code, path, next) = fail(&ITEM_LIST, &long);
    assert_eq!(
        (code.as_str(), path.as_str()),
        ("LIMIT_EXCEEDED", "/filter/name")
    );
    let cut = next.expect("a clamp");
    assert_eq!(
        cut.pointer("/filter/name")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );
    assert_eq!(
        fail(&ITEM_LIST, r#"{"filter":{"name":5}}"#).0,
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        fail(&ECHO_VALUE, r#"{"value":1,"flag":"yes"}"#).0,
        "INVALID_ARGUMENT"
    );
    assert!(parse(&ECHO_VALUE, &json(r#"{"value":1,"tag":"set:x"}"#), None).is_ok());
    let error =
        parse(&ECHO_VALUE, &json(r#"{"value":1,"tag":"fn:0x1"}"#), None).expect_err("a kind");
    let expected = error
        .details
        .as_ref()
        .and_then(|d| d.get("expected"))
        .and_then(Value::as_str);
    assert!(
        expected.is_some_and(|e| e.contains("note:") && e.contains("set:")),
        "{expected:?}"
    );
    assert_eq!(
        fail(&ECHO_VALUE, r#"{"value":1,"tag":7}"#).0,
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        fail(&ECHO_VALUE, r#"{"value":1,"tag":"note:"}"#).0,
        "INVALID_ARGUMENT"
    );
    assert_eq!(fail(&ECHO_VALUE, "{}").0, "MISSING_ARGUMENT");
    assert!(parse(&ECHO_VALUE, &json(r#"{"value":[{"deep":null}]}"#), None).is_ok());
    assert_eq!(fail(&ECHO_VALUE, "[1]").0, "INVALID_ARGUMENT");
}

#[test]
fn groups_and_defaults() {
    let (code, _, _) = fail(&ITEM_GET, "{}");
    assert_eq!(code, "MISSING_ARGUMENT");
    let error = parse(&ITEM_GET, &json("{}"), None).expect_err("a group");
    assert_eq!(
        error.details.as_ref().and_then(|d| d.get("group")),
        Some(&json(r#"["target","targets"]"#))
    );
    let (code, path, _) = fail(&ITEM_GET, r#"{"target":"0x1","targets":["0x2"]}"#);
    assert_eq!(
        (code.as_str(), path.as_str()),
        ("INVALID_ARGUMENT", "/targets")
    );
    let parsed = parse(&ITEM_LIST, &json("{}"), None).expect("a parse");
    let args = parsed.args;
    assert_eq!(args.tool(), "item_list");
    assert_eq!(args.int("count"), Some(40));
    assert!(!args.given("count"));
    assert_eq!(args.str("sort"), Some("addr"));
    assert!(args.get("filter").is_none());
    assert_eq!(args.values().count(), 2);
    let args = parse(
        &ITEM_EDIT,
        &json(r#"{"action":"delete","target":"0x401000"}"#),
        None,
    )
    .expect("a parse")
    .args;
    assert_eq!(args.action(), Some("delete"));
    assert!(args.given("target"));
    assert_eq!(args.bool("target"), None);
    assert!(args.list("evidence").is_none());
    let args = parse(&ITEM_LIST, &json(r#"{"count":3}"#), None)
        .expect("a parse")
        .args;
    assert_eq!(args.action(), None);
}

#[test]
fn globals_parse_and_apply() {
    assert_eq!(
        names(&ECHO_VALUE),
        ["format", "fields", "max_chars", "session"]
    );
    assert_eq!(
        names(&ITEM_LIST),
        [
            "binary_id",
            "format",
            "fields",
            "max_chars",
            "limit",
            "cursor",
            "count_only",
            "shape",
            "in",
            "session"
        ]
    );
    assert_eq!(
        names(&ITEM_EDIT),
        [
            "binary_id",
            "format",
            "fields",
            "max_chars",
            "session",
            "expected_rev",
            "dry_run",
            "force"
        ]
    );
    assert_eq!(
        names(&FUEL_RUN),
        [
            "binary_id",
            "format",
            "fields",
            "max_chars",
            "session",
            "max_steps",
            "max_ms"
        ]
    );
    let fuel = globals_of(&FUEL_RUN);
    let max_steps = fuel
        .iter()
        .find(|g| g.name == "max_steps")
        .expect("max_steps");
    assert_eq!(
        max_steps.kind,
        ArgKind::Int {
            min: 1,
            max: 100_000
        }
    );
    let args = parse(
        &ITEM_LIST,
        &json(r#"{"binary_id":"b1","format":"detailed","fields":["/items"],"max_chars":5000,"limit":7,"cursor":"c","count_only":true,"shape":"table","in":"set:a","session":"s"}"#),
        None,
    )
    .expect("a parse")
    .args;
    let g = args.globals();
    assert_eq!(g.binary_id.as_deref(), Some("b1"));
    assert_eq!(g.format, Format::Detailed);
    assert_eq!(g.fields.len(), 1);
    assert_eq!((g.max_chars, g.limit), (Some(5_000), Some(7)));
    assert_eq!(g.cursor.as_deref(), Some("c"));
    assert!(g.count_only);
    assert_eq!(g.shape, Shape::Table);
    assert_eq!(g.in_set.as_deref(), Some("set:a"));
    assert_eq!(g.session.as_deref(), Some("s"));
    let args = parse(
        &ITEM_EDIT,
        &json(r#"{"action":"delete","target":"0x1","expected_rev":4,"dry_run":true,"force":true}"#),
        None,
    )
    .expect("a parse")
    .args;
    let g = args.globals();
    assert_eq!(g.expected_rev, Some(4));
    assert!(g.dry_run && g.force);
    let args = parse(
        &FUEL_RUN,
        &json(r#"{"work":1,"max_steps":9,"max_ms":10}"#),
        None,
    )
    .expect("a parse")
    .args;
    assert_eq!(
        (args.globals().max_steps, args.globals().max_ms),
        (Some(9), Some(10))
    );
    assert_eq!(fail(&ITEM_LIST, r#"{"limit":0}"#).0, "INVALID_ARGUMENT");
    assert_eq!(fail(&ITEM_LIST, r#"{"limit":1001}"#).0, "LIMIT_EXCEEDED");
    assert_eq!(fail(&ITEM_LIST, r#"{"in":"fn:0x1"}"#).0, "INVALID_ARGUMENT");
    let parsed = parse(&ITEM_GET, &json(r#"{"id":"0x1"}"#), None).expect("an alias");
    assert_eq!(parsed.warnings.len(), 1);
    assert!(parsed.args.given("target"));
    assert_eq!(
        parse_strict(&ITEM_GET, &json(r#"{"id":"0x1"}"#)).map_err(|e| e.code.name()),
        Err("UNKNOWN_ARGUMENT")
    );
    let coerce = |kind: &ArgKind, value: &Value| match (kind, value) {
        (ArgKind::Bool, Value::String(s)) if s == "true" => Some(Value::Bool(true)),
        _ => None,
    };
    let parsed = parse(
        &ECHO_VALUE,
        &json(r#"{"value":1,"flag":"true"}"#),
        Some(&coerce),
    )
    .expect("a coercion");
    assert_eq!(parsed.args.bool("flag"), Some(true));
    assert_eq!(parsed.warnings.len(), 1);
    let error = parse(
        &ECHO_VALUE,
        &json(r#"{"value":1,"flag":"no"}"#),
        Some(&coerce),
    )
    .expect_err("no coercion");
    assert_eq!(error.code.name(), "INVALID_ARGUMENT");
}
