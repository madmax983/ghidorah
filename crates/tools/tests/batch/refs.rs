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
    let found = error_candidates(&envelope, None);
    assert!(!found.is_empty(), "{envelope}");
    assert!(found.iter().all(|c| c.starts_with("/data")), "{found:?}");

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
    let found = error_candidates(&envelope, Some(1));
    assert!(!found.is_empty(), "{envelope}");
    assert!(found.iter().all(|c| c.starts_with("/data")), "{found:?}");

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
            {"id":"s2","tool":"func_get","args":{"targets":{"$ref":"s1","ptr":"/data/rows/*/a"}}}
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

/// Gives the candidate values of the error of a batch, or of its step entry `step`.
fn error_candidates(envelope: &Value, step: Option<usize>) -> Vec<String> {
    let error = match step {
        Some(i) => steps(envelope)
            .get(i)
            .and_then(|s| s.get("error").cloned())
            .unwrap_or_default(),
        None => envelope.get("error").cloned().unwrap_or_default(),
    };
    candidates(&error)
}

/// A type mismatch gives the paths of the source data as candidates, before the run and at
/// run time (found by the round 4 review).
#[test]
fn regress_type_mismatch_ref_has_candidates() {
    let mut s = demo();
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{"limit":3}},
            {"id":"s2","tool":"calc","args":{"expr":{"$ref":"s1","ptr":"/data/items/0/size"}}}
        ]}"#,
    );
    assert_eq!(code(&envelope), "BAD_REFERENCE", "{envelope}");
    let found = error_candidates(&envelope, None);
    assert!(!found.is_empty(), "{envelope}");
    assert!(found.iter().all(|c| c.starts_with("/data")), "{found:?}");
    // The paths that fit a string argument come first, and they need no star.
    assert!(
        found.contains(&"/data/items/0/name".to_owned()),
        "{found:?}"
    );
    assert!(!found.iter().any(|c| c.contains('*')), "{found:?}");
    // A star pointer into a list argument keeps the star in its candidates.
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{"limit":3}},
            {"id":"s2","tool":"func_get","args":{"targets":{"$ref":"s1","ptr":"/data/items/*/visited"}}}
        ]}"#,
    );
    assert_eq!(code(&envelope), "BAD_REFERENCE", "{envelope}");
    let found = error_candidates(&envelope, None);
    assert!(found.contains(&"/data/items/*/id".to_owned()), "{found:?}");
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"tool_search","args":{"name":"calc","level":"full"}},
            {"id":"s2","tool":"calc","args":{"expr":{"$ref":"s1","ptr":"/data/items/0/schema"}}}
        ]}"#,
    );
    assert_eq!(step_code(&envelope, 1), "BAD_REFERENCE", "{envelope}");
    let found = error_candidates(&envelope, Some(1));
    assert!(!found.is_empty(), "{envelope}");
    assert!(found.iter().all(|c| c.starts_with("/data")), "{found:?}");
    assert!(
        found.contains(&"/data/items/0/name".to_owned()),
        "{found:?}"
    );
}

/// A batch whose references to the completed step `s1` fail at run time. The step `look`
/// stops on a small fuel budget. The `keep` step binds the object at `/data/items/0/schema`.
/// The `mismatch` step reads that object into a text argument. The `typo` step reads a path
/// that the data does not have.
const FAILING_REFS: &str = r#"[
    {"id":"s1","tool":"tool_search","args":{"name":"calc","level":"full"}},
    {"id":"look","tool":"search","args":{"kind":"name","query":"pass"}},
    {"id":"keep","tool":"fact_check","args":{"claims":[{"rel":"calls",
        "args":[{"$ref":"s1","ptr":"/data/items/0/schema"},"main"]}]}},
    {"id":"mismatch","tool":"calc","args":{"expr":{"$ref":"s1","ptr":"/data/items/0/schema"}}},
    {"id":"typo","tool":"calc","args":{"expr":{"$ref":"s1","ptr":"/data/items/0/schema/nope"}}}
]"#;

/// A replay of a batch that stopped on fuel gives the reference errors of a first run, with
/// the same candidates (found by the round 5 review).
#[test]
fn regress_batch_resume_ref_keeps_candidates() {
    let mut s = demo();
    let unlimited = batch(&mut s, &format!(r#"{{"steps":{FAILING_REFS}}}"#));
    let first = steps(&unlimited);
    for entry in &first[3..] {
        assert_eq!(
            text_at(entry, "/error/code"),
            "BAD_REFERENCE",
            "{unlimited}"
        );
        let error = entry.get("error").cloned().unwrap_or_default();
        assert!(!candidates(&error).is_empty(), "{unlimited}");
    }
    // The same batch stops on fuel after `s1`.
    let fuel = first[0].get("fuel").and_then(Value::as_u64).unwrap_or(0);
    let text = format!(
        r#"{{"steps":{FAILING_REFS},"max_steps":{}}}"#,
        fuel.saturating_add(1)
    );
    let stopped = batch(&mut s, &text);
    let resume = stopped
        .pointer("/data/resume")
        .cloned()
        .unwrap_or_else(|| panic!("the batch gives resume: {stopped}"));
    assert_eq!(text_at(&resume, "/from_step"), "look", "{stopped}");
    // The replay binds `s1` and gives the error of the first run at each failed reference.
    let replay = Value::object([
        ("steps", crate::support::json(FAILING_REFS)),
        ("resume", resume.clone()),
    ]);
    let envelope = call_value(&mut s, "batch_run", replay);
    let again = steps(&envelope);
    assert_eq!(
        again[0].get("resumed"),
        Some(&Value::Bool(true)),
        "{envelope}"
    );
    for (got, want) in again[3..].iter().zip(&first[3..]) {
        assert_eq!(got.get("error"), want.get("error"), "{envelope}");
    }
    // A replay that stops again gives the same bindings, from the bindings of `s1`.
    let replay = Value::object([
        ("steps", crate::support::json(FAILING_REFS)),
        ("resume", resume.clone()),
        ("max_steps", Value::from(1)),
    ]);
    let envelope = call_value(&mut s, "batch_run", replay);
    assert_eq!(
        envelope.pointer("/data/resume"),
        Some(&resume),
        "{envelope}"
    );
}

/// A replay reads a reference through the bindings of its source step, each at its pointer.
/// A binding through a text or through a missing array item has no place.
#[test]
fn replay_reads_bindings_by_pointer() {
    let mut s = demo();
    let steps_text = r#"[
        {"id":"s1","tool":"tool_search","args":{"name":"calc","level":"full"}},
        {"id":"look","tool":"search","args":{"kind":"name","query":"pass"}},
        {"id":"name","tool":"search","args":{"kind":"name","query":{"$ref":"s1","ptr":"/data/items/0/name"}}},
        {"id":"mismatch","tool":"calc","args":{"expr":{"$ref":"s1","ptr":"/data/items/0/schema"}}},
        {"id":"typo","tool":"calc","args":{"expr":{"$ref":"s1","ptr":"/data/items/0/schema/nope"}}}
    ]"#;
    let bindings = r#"[
        {"step":"s1","ptr":"","value":{"data":{"items":[{"name":"calc"}]}}},
        {"step":"s1","ptr":"/data/items/0","value":{"name":"calc","schema":{"type":"object"}}},
        {"step":"s1","ptr":"/data/items/0/name/x","value":1},
        {"step":"s1","ptr":"/data/items/0/name/x/y","value":2},
        {"step":"s1","ptr":"/data/items/9","value":"lost"},
        {"step":"s1","ptr":"/data/items/9/name","value":"lost"},
        {"step":"s1","ptr":"/data/items/*/name","value":["calc"]}
    ]"#;
    let text = format!(
        r#"{{"steps":{steps_text},"resume":{{"from_step":"look","bindings":{bindings}}}}}"#
    );
    let envelope = batch(&mut s, &text);
    let entries = steps(&envelope);
    assert_eq!(text_at(&entries[2], "/error/code"), "", "{envelope}");
    let sorted = |i: usize| {
        let error = entries[i].get("error").cloned().unwrap_or_default();
        assert_eq!(text_at(&error, "/code"), "BAD_REFERENCE", "{envelope}");
        let mut found = candidates(&error);
        found.sort();
        found
    };
    // The text paths of the bound data fit the text argument.
    assert_eq!(
        sorted(3),
        ["/data/items/0/name", "/data/items/0/schema/type"],
        "{envelope}"
    );
    // A missing path gives every path of the bound data.
    assert_eq!(
        sorted(4),
        [
            "/data/items",
            "/data/items/0/name",
            "/data/items/0/schema",
            "/data/items/0/schema/type"
        ],
        "{envelope}"
    );
}

/// The repair call of `PLUCK_TOO_LONG` runs: the source step gets a limit, and the reference
/// accepts the truncated page (found by WP-26).
#[test]
fn regress_pluck_repair_runs() {
    let mut s = demo();
    let envelope = batch(
        &mut s,
        r#"{"steps":[
            {"id":"s1","tool":"func_list","args":{}},
            {"id":"s2","tool":"fact_check","args":{"explain":{"$ref":"s1","ptr":"/data/items/*/id"}}}
        ]}"#,
    );
    assert_eq!(step_code(&envelope, 1), "PLUCK_TOO_LONG", "{envelope}");
    let (tool, fixed) = next0(&envelope);
    assert_eq!(tool, "batch_run");
    let again = call_value(&mut s, "batch_run", fixed);
    assert_eq!(step_code(&again, 1), "", "{again}");
    assert_eq!(again.get("ok"), Some(&Value::Bool(true)), "{again}");
}
