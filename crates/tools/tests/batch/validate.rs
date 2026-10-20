//! The checks before the run (AC-176a, AC-176b, AC-180, AC-181c, AC-181d, AC-219).

use ghidorah_json::Value;
use ghidorah_tools::args::parse_strict;
use ghidorah_tools::batch::{DESTRUCTIVE, STEP_GLOBALS};
use ghidorah_tools::{Profile, Session};

use crate::support::{
    batch, call, call_value, code, data, demo, demo_in, full_registry, json, lines, next0, rev,
    state_hash, steps, text_at,
};

/// The first step of the invalid batches: an edit. A batch that runs it changes the rev.
const RENAME: &str =
    r#"{"id":"a","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}}"#;

/// Gives the batch text with [`RENAME`] and `second` as its steps.
fn with_second(second: &str) -> String {
    format!(r#"{{"steps":[{RENAME},{second}]}}"#)
}

/// Runs `text` and makes sure that the batch fails before any step ran. Gives the envelope.
fn rejected(s: &mut Session, text: &str) -> Value {
    let (rev0, hash0, lines0) = (rev(s), state_hash(s), lines(s));
    let envelope = batch(s, text);
    assert_eq!(envelope.get("ok"), Some(&Value::Bool(false)), "{envelope}");
    assert_eq!(rev(s), rev0, "no step ran: {envelope}");
    assert_eq!(state_hash(s), hash0);
    assert_eq!(lines(s), lines0);
    envelope
}

/// Gives the `value` of each candidate of an error envelope.
fn candidates(envelope: &Value) -> Vec<String> {
    envelope
        .pointer("/error/candidates")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|c| text_at(c, "/value"))
        .collect()
}

/// Makes sure that the repair call `next[0]` of `envelope` is a valid batch.
fn repair_parses(envelope: &Value) -> Value {
    let (tool, args) = next0(envelope);
    assert_eq!(tool, "batch_run", "{envelope}");
    let registry = full_registry();
    let (_, spec) = registry.get("batch_run").expect("batch_run is registered");
    parse_strict(spec, &args).unwrap_or_else(|e| panic!("{e}: {args}"));
    args
}

#[test]
fn ac_176a_static_validation() {
    let mut s = demo();
    let envelope = rejected(
        &mut s,
        &with_second(r#"{"id":"b","tool":"func_gte","args":{"target":"main"}}"#),
    );
    assert_eq!(code(&envelope), "UNKNOWN_TOOL");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/steps/1/tool");
    assert!(
        candidates(&envelope).contains(&"func_get".to_owned()),
        "{envelope}"
    );
    let (tool, args) = next0(&envelope);
    assert_eq!(
        (tool.as_str(), text_at(&args, "/query")),
        ("tool_search", "func_gte".to_owned())
    );

    let envelope = rejected(
        &mut s,
        &with_second(r#"{"id":"b","tool":"func_get","args":{"targt":"main"}}"#),
    );
    assert_eq!(code(&envelope), "UNKNOWN_ARGUMENT");
    assert_eq!(
        text_at(&envelope, "/error/field_path"),
        "/steps/1/args/targt"
    );
    assert!(candidates(&envelope).contains(&"target".to_owned()));
    let fixed = repair_parses(&envelope);
    assert_eq!(text_at(&fixed, "/steps/1/args/target"), "main", "{fixed}");
    let again = call_value(&mut s, "batch_run", fixed);
    assert_eq!(again.get("ok"), Some(&Value::Bool(true)), "{again}");

    let mut s = demo();
    let envelope = rejected(
        &mut s,
        &with_second(r#"{"id":"a","tool":"calc","args":{"expr":"0x1"}}"#),
    );
    assert_eq!(code(&envelope), "INVALID_ARGUMENT");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/steps/1/id");

    let envelope = rejected(
        &mut s,
        r#"{"steps":[{"id":"S1","tool":"calc","args":{"expr":"0x1"}}]}"#,
    );
    assert_eq!(code(&envelope), "INVALID_ARGUMENT");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/steps/0/id");

    let envelope = rejected(&mut s, &format!(r#"{{"steps":[{RENAME}],"return":["b"]}}"#));
    assert_eq!(code(&envelope), "INVALID_ARGUMENT");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/return/0");
    assert_eq!(candidates(&envelope), ["a"]);

    let envelope = rejected(
        &mut s,
        &with_second(r#"{"id":"b","tool":"func_get","args":{}}"#),
    );
    assert_eq!(code(&envelope), "MISSING_ARGUMENT", "{envelope}");
    assert!(
        text_at(&envelope, "/error/field_path").starts_with("/steps/1/args/"),
        "{envelope}"
    );
    let (tool, args) = next0(&envelope);
    assert_eq!(tool, "tool_search");
    assert_eq!(text_at(&args, "/name"), "func_get");

    let envelope = rejected(&mut s, r#"{"steps":[]}"#);
    assert_eq!(code(&envelope), "INVALID_ARGUMENT");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/steps");

    let envelope = rejected(
        &mut s,
        r#"{"steps":[{"id":"a","tool":"func_get","args":{"targets":{"$ref":"b","ptr":"/data/items/*/id"}}},{"id":"b","tool":"func_list"}]}"#,
    );
    assert_eq!(code(&envelope), "BAD_REFERENCE");
    assert_eq!(
        text_at(&envelope, "/error/field_path"),
        "/steps/0/args/targets"
    );

    let envelope = rejected(
        &mut s,
        &with_second(r#"{"id":"b","tool":"calc","args":"0x1"}"#),
    );
    assert_eq!(code(&envelope), "INVALID_ARGUMENT");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/steps/1/args");

    let envelope = rejected(
        &mut s,
        &with_second(
            r#"{"id":"b","tool":"func_list","expect":[{"ptr":"data/items","op":"exists"}]}"#,
        ),
    );
    assert_eq!(code(&envelope), "INVALID_ARGUMENT");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/steps/1/expect/0");
}

#[test]
fn ac_176b_globals_in_steps() {
    let start = rev(&demo()).to_string();
    let values = [
        ("binary_id", r#""467a43b75d95c826""#),
        ("max_chars", "20000"),
        ("max_steps", "100000"),
        ("dry_run", "true"),
        ("expected_rev", start.as_str()),
        ("session", r#""agent-2""#),
    ];
    assert_eq!(values.len(), STEP_GLOBALS.len());
    for (key, value) in values {
        assert!(STEP_GLOBALS.contains(&key));
        let mut s = demo();
        let text = format!(
            r#"{{"steps":[{{"id":"a","tool":"symbol_rename","args":{{"target":"0x1090","name":"read_input","{key}":{value}}}}}]}}"#
        );
        let envelope = rejected(&mut s, &text);
        assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{key}: {envelope}");
        assert_eq!(
            text_at(&envelope, "/error/field_path"),
            format!("/steps/0/args/{key}")
        );
        let fixed = repair_parses(&envelope);
        assert_eq!(fixed.get(key), Some(&json(value)), "{key}: {fixed}");
        assert!(fixed.pointer(&format!("/steps/0/args/{key}")).is_none());
        let again = call_value(&mut s, "batch_run", fixed);
        assert_eq!(again.get("ok"), Some(&Value::Bool(true)), "{key}: {again}");
    }
    // A key at both levels keeps the top-level value.
    let mut s = demo();
    let envelope = rejected(
        &mut s,
        r#"{"steps":[{"id":"a","tool":"calc","args":{"expr":"0x1","max_chars":9000}}],"max_chars":12000}"#,
    );
    let fixed = repair_parses(&envelope);
    assert_eq!(fixed.get("max_chars"), Some(&json("12000")));
}

#[test]
fn ac_180_readonly() {
    let mut s = demo_in(Profile::Readonly);
    let text = r#"{"steps":[
        {"id":"look","tool":"func_get","args":{"target":"fn:0x11e0","include":["disasm"]}},
        {"id":"edit","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}}
    ]}"#;
    let envelope = rejected(&mut s, text);
    assert_eq!(code(&envelope), "TOOL_NOT_IN_PROFILE", "{envelope}");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/steps/1/tool");
    let visited = call(&mut s, "func_list", r#"{"filter":{"visited":true}}"#);
    assert_eq!(
        visited.pointer("/page/total").and_then(Value::as_u64),
        Some(0),
        "the first step did not run: {visited}"
    );
    let envelope = batch(
        &mut s,
        r#"{"steps":[{"id":"look","tool":"func_list","args":{"limit":2}}]}"#,
    );
    assert_eq!(steps(&envelope).len(), 1, "{envelope}");
    let list = s.config().profile.tools_list(&s.active_registry());
    let entry = list
        .as_array()
        .unwrap_or_default()
        .iter()
        .find(|t| text_at(t, "/name") == "batch_run")
        .cloned()
        .expect("batch_run is in readonly");
    assert_eq!(
        entry.pointer("/annotations/readOnlyHint"),
        Some(&Value::Bool(true))
    );
}

#[test]
fn ac_181c_no_nesting() {
    for tool in ["batch_run", "binary_load", "analysis_run"] {
        let mut s = demo();
        let text = with_second(&format!(r#"{{"id":"b","tool":"{tool}","args":{{}}}}"#));
        let envelope = rejected(&mut s, &text);
        assert_eq!(code(&envelope), "INVALID_ARGUMENT", "{tool}: {envelope}");
        assert_eq!(text_at(&envelope, "/error/field_path"), "/steps/1/tool");
    }
}

#[test]
fn ac_181d_step_cap() {
    let step = |i: usize| format!(r#"{{"id":"s{i}","tool":"calc","args":{{"expr":"0x{i:x}"}}}}"#);
    let all: Vec<String> = (0..33).map(step).collect();
    let mut s = demo();
    let envelope = rejected(&mut s, &format!(r#"{{"steps":[{}]}}"#, all.join(",")));
    assert_eq!(code(&envelope), "LIMIT_EXCEEDED", "{envelope}");
    assert_eq!(text_at(&envelope, "/error/field_path"), "/steps");
    let fixed = repair_parses(&envelope);
    assert_eq!(
        fixed
            .get("steps")
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(32)
    );
    let again = call_value(&mut s, "batch_run", fixed);
    assert_eq!(steps(&again).len(), 32, "{again}");
    let thirty_two = &all[..32];
    let envelope = batch(
        &mut s,
        &format!(r#"{{"steps":[{}]}}"#, thirty_two.join(",")),
    );
    assert_eq!(steps(&envelope).len(), 32);
}

#[test]
fn ac_219_destructive_rejected() {
    let cases = [
        (
            r#"{"id":"b","tool":"history_undo","args":{}}"#,
            "history_undo",
        ),
        (
            r#"{"id":"b","tool":"func_edit","args":{"action":"delete","target":"fn:0x11e0"}}"#,
            "func_edit",
        ),
        (
            r#"{"id":"b","tool":"func_edit","args":{"action":"remove_ref","ref":{"from":"0x1091","to":"0x11e0","kind":"unconditional_call"}}}"#,
            "func_edit",
        ),
    ];
    for (second, tool) in cases {
        let mut s = demo();
        let envelope = rejected(&mut s, &with_second(second));
        assert_eq!(code(&envelope), "TOOL_NOT_IN_PROFILE", "{envelope}");
        assert_eq!(
            text_at(&envelope, "/error/details/reason"),
            DESTRUCTIVE,
            "{envelope}"
        );
        assert_eq!(text_at(&envelope, "/error/field_path"), "/steps/1/tool");
        let (next, args) = next0(&envelope);
        assert_eq!(next, tool, "next[0] is the direct call: {envelope}");
        let step = json(second);
        assert_eq!(Some(&args), step.get("args"), "{envelope}");
    }
    // A direct call accepts a destructive action, and a batch accepts a safe action.
    let mut s = demo();
    let envelope = batch(
        &mut s,
        r#"{"steps":[{"id":"a","tool":"func_edit","args":{"action":"set_noreturn","target":"fn:0x11e0","noreturn":true}}]}"#,
    );
    assert_eq!(envelope.get("ok"), Some(&Value::Bool(true)), "{envelope}");
    let direct = call(
        &mut s,
        "func_edit",
        r#"{"action":"delete","target":"fn:0x11e0"}"#,
    );
    let _ = data(&direct);
}

/// A step outside the profile gets a hint that names the profile, the active tools with close
/// names and a search of the active tools.
#[test]
fn regress_batch_step_not_in_profile_repair() {
    let mut s = demo_in(Profile::Mini);
    let text = r#"{"steps":[{"id":"c","tool":"comment_set","args":{"target":"0x1090","kind":"eol","text":"x"}}]}"#;
    let envelope = rejected(&mut s, text);
    assert_eq!(code(&envelope), "TOOL_NOT_IN_PROFILE", "{envelope}");
    assert_eq!(
        text_at(&envelope, "/error/details/reason"),
        "not_in_profile"
    );
    let hint = text_at(&envelope, "/error/hint");
    assert!(hint.contains("mini"), "{envelope}");
    assert!(hint.contains("--profile full"), "{envelope}");
    let (tool, args) = next0(&envelope);
    assert_eq!(tool, "tool_search", "{envelope}");
    assert_eq!(text_at(&args, "/query"), "comment_set", "{envelope}");
    let text =
        r#"{"steps":[{"id":"c","tool":"func_edit","args":{"action":"create","target":"0x1090"}}]}"#;
    let envelope = rejected(&mut s, text);
    assert!(
        candidates(&envelope).contains(&"func_get".to_owned()),
        "{envelope}"
    );
}
