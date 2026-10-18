//! References between steps (AC-179a, AC-179b, AC-179c).

use ghidorah_json::Value;

use crate::support::{batch, call_value, code, demo, next0, rev, step_code, steps, text_at};

/// Gives the `value` of each candidate of an error object.
fn candidates(error: &Value) -> Vec<String> {
    error
        .get("candidates")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|c| text_at(c, "/value"))
        .collect()
}

#[test]
fn ac_179a_bad_refs() {
    let mut s = demo();
    // A typo in the step ID: the batch fails before the run.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{"limit":3}},
            {"id":"s2","tool":"func_get","args":{"targets":{"$ref":"s9","ptr":"/data/items/*/id"}}}
        ]}"#,
    );
    assert_eq!(code(&envelope), "BAD_REFERENCE", "{envelope}");
    assert_eq!(
        text_at(&envelope, "/error/field_path"),
        "/steps/1/args/targets"
    );
    let error = envelope.get("error").cloned().unwrap_or_default();
    assert_eq!(candidates(&error), ["s1"]);

    // A path that the output shape does not have.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{"limit":3}},
            {"id":"s2","tool":"func_get","args":{"targets":{"$ref":"s1","ptr":"/data/items/*/idd"}}}
        ]}"#,
    );
    assert_eq!(code(&envelope), "BAD_REFERENCE", "{envelope}");
    let error = envelope.get("error").cloned().unwrap_or_default();
    assert!(
        candidates(&error).contains(&"/data/items/*/id".to_owned()),
        "{envelope}"
    );

    // A type mismatch before the run: an integer into a string argument.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{"limit":3}},
            {"id":"s2","tool":"calc","args":{"expr":{"$ref":"s1","ptr":"/data/items/0/size"}}}
        ]}"#,
    );
    assert_eq!(code(&envelope), "BAD_REFERENCE", "{envelope}");
    assert_eq!(
        text_at(&envelope, "/error/field_path"),
        "/steps/1/args/expr"
    );

    // A star reference into an argument that is not a list.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{"limit":3}},
            {"id":"s2","tool":"func_get","args":{"target":{"$ref":"s1","ptr":"/data/items/*/id"}}}
        ]}"#,
    );
    assert_eq!(code(&envelope), "BAD_REFERENCE", "{envelope}");

    // A pointer that does not parse.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{"limit":3}},
            {"id":"s2","tool":"func_get","args":{"target":{"$ref":"s1","ptr":"data/items/0/id"}}}
        ]}"#,
    );
    assert_eq!(code(&envelope), "BAD_REFERENCE", "{envelope}");

    // An index out of range: the step fails at run time with the available paths.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{"limit":2}},
            {"id":"s2","tool":"func_get","args":{"target":{"$ref":"s1","ptr":"/data/items/7/id","partial":true}}}
        ]}"#,
    );
    assert_eq!(step_code(&envelope, 1), "BAD_REFERENCE", "{envelope}");
    let error = steps(&envelope)[1]
        .get("error")
        .cloned()
        .unwrap_or_default();
    assert!(!candidates(&error).is_empty(), "{envelope}");
    assert!(
        candidates(&error).iter().all(|c| c.starts_with("/data")),
        "{envelope}"
    );

    // A type mismatch at run time: a schema object into a string argument.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"tool_search","args":{"name":"calc","level":"full"}},
            {"id":"s2","tool":"calc","args":{"expr":{"$ref":"s1","ptr":"/data/items/0/schema"}}}
        ]}"#,
    );
    assert_eq!(step_code(&envelope, 1), "BAD_REFERENCE", "{envelope}");

    // A reference never becomes null, and a good reference takes the value.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{"filter":{"name":"check_*"}}},
            {"id":"s2","tool":"func_get","args":{"target":{"$ref":"s1","ptr":"/data/items/0/id"}}}
        ]}"#,
    );
    assert_eq!(
        text_at(&envelope, "/data/steps/1/data/name"),
        "check_password",
        "{envelope}"
    );
}

#[test]
fn ac_179b_star_cap() {
    let mut s = demo();
    let rev0 = rev(&s);
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"search","args":{"kind":"name","query":"","limit":80}},
            {"id":"s2","tool":"func_get","args":{"targets":{"$ref":"s1","ptr":"/data/items/*/id"}}}
        ]}"#,
    );
    assert_eq!(code(&envelope), "LIMIT_EXCEEDED", "{envelope}");
    assert_eq!(
        text_at(&envelope, "/error/field_path"),
        "/steps/0/args/limit"
    );
    let (tool, fixed) = next0(&envelope);
    assert_eq!(tool, "batch_run");
    assert_eq!(fixed.pointer("/steps/0/args/limit"), Some(&Value::from(50)));
    assert_eq!(rev(&s), rev0);
    let again = call_value(&mut s, "batch_run", fixed);
    assert_eq!(again.get("ok"), Some(&Value::Bool(true)), "{again}");

    // At run time, more values than the cap give PLUCK_TOO_LONG.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"mem_read","args":{"target":"0x1080","as":"insn","count":80}},
            {"id":"s2","tool":"func_get","args":{"targets":{"$ref":"s1","ptr":"/data/rows/*/addr"}}}
        ]}"#,
    );
    assert_eq!(step_code(&envelope, 1), "PLUCK_TOO_LONG", "{envelope}");

    // A star reference removes duplicates and keeps the first order.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"xref_list","args":{"targets":["fn:0x11e0","fn:0x11e0"]}},
            {"id":"s2","tool":"addr_info","args":{"targets":{"$ref":"s1","ptr":"/data/items/*/to"}}}
        ]}"#,
    );
    let items = envelope
        .pointer("/data/steps/1/data/items")
        .and_then(Value::as_array)
        .map(<[Value]>::len);
    assert_eq!(items, Some(1), "{envelope}");
}

#[test]
fn ac_179c_truncated_source() {
    let mut s = demo();
    let text = |partial: &str| {
        format!(
            r#"{{"steps":[
                {{"id":"s1","tool":"func_list","args":{{"limit":2}}}},
                {{"id":"s2","tool":"func_get","args":{{"targets":{{"$ref":"s1","ptr":"/data/items/*/id"{partial}}}}}}}
            ]}}"#
        )
    };
    let envelope = batch(&mut s, &text(""));
    assert_eq!(
        envelope.pointer("/data/steps/0/page/truncated"),
        Some(&Value::Bool(true)),
        "{envelope}"
    );
    assert_eq!(step_code(&envelope, 1), "BAD_REFERENCE", "{envelope}");
    assert_eq!(
        envelope.pointer("/data/steps/1/error/details/source_truncated"),
        Some(&Value::Bool(true))
    );
    let envelope = batch(&mut s, &text(r#","partial":true"#));
    assert_eq!(
        envelope.pointer("/data/steps/1/ok"),
        Some(&Value::Bool(true)),
        "{envelope}"
    );
    let items = envelope
        .pointer("/data/steps/1/data/items")
        .and_then(Value::as_array)
        .map(<[Value]>::len);
    assert_eq!(items, Some(2), "{envelope}");
}
