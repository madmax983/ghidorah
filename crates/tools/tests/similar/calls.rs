//! `func_similar` calls: determinism (AC-239), the caps of `min_score` and `limit`, the
//! output members and the `next` hints without binary names.

use std::collections::BTreeSet;

use ghidorah_json::Value;
use ghidorah_tools::Profile;

use crate::support::{
    FULL, STRIPPED, call, call_value, code, data, default_named, int_at, list_at, next_calls, open,
    open_in, program, similar_args, text_at,
};

/// Gives the arguments of a proposal call over up to 20 default-named functions of `id`.
fn proposal_args(session: &ghidorah_tools::Session, id: ghidorah_base::BinaryId) -> Value {
    let targets: Vec<Value> = default_named(session, id)
        .into_iter()
        .take(20)
        .map(Value::from)
        .collect();
    assert!(targets.len() >= 3, "{} default names", targets.len());
    let mut args = similar_args(id, r#"{"scope":"open","propose_names":true}"#);
    if let Value::Object(object) = &mut args {
        object.push("targets", Value::Array(targets));
    }
    args
}

#[test]
fn ac_239_similar_deterministic() {
    let run = || {
        let (mut s, ids) = open(&[STRIPPED, FULL]);
        let args = proposal_args(&s, ids[0]);
        let first = call_value(&mut s, "func_similar", args.clone());
        let again = call_value(&mut s, "func_similar", args);
        assert_eq!(first, again, "a second call in one session");
        let one = call(
            &mut s,
            "func_similar",
            &format!(
                r#"{{"binary_id":"{}","target":"main","min_score":0}}"#,
                ids[1]
            ),
        );
        (ghidorah_json::write(&first), ghidorah_json::write(&one))
    };
    let (a, b) = (run(), run());
    assert_eq!(a, b, "two sessions give byte-equal results");
    assert!(a.0.contains("\"proposal\""), "{}", a.0);
    assert!(a.1.contains("\"top_features\""), "{}", a.1);
}

#[test]
fn min_score_and_limit_caps() {
    let (mut s, ids) = open(&[FULL]);
    let envelope = call(
        &mut s,
        "func_similar",
        r#"{"target":"main","min_score":0,"limit":3}"#,
    );
    let d = data(&envelope);
    let items = list_at(d, "/items");
    assert_eq!(items.len(), 1);
    let matches = list_at(&items[0], "/matches");
    assert_eq!(matches.len(), 3, "{envelope}");
    let scores: Vec<u64> = matches.iter().map(|m| int_at(m, "/score")).collect();
    let mut sorted = scores.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(scores, sorted, "score order");
    assert!(scores.iter().all(|s| *s <= 1_000));
    assert_eq!(text_at(&items[0], "/query/id"), "fn:0x1080");
    assert_eq!(text_at(&items[0], "/query/binary_id"), ids[0].to_string());
    assert!(int_at(&items[0], "/query/features") > 10);
    assert_eq!(int_at(d, "/corpus/binaries"), 1);
    let functions = int_at(d, "/corpus/functions");
    let count = u64::try_from(program(&s, ids[0]).funcs().len()).expect("a count");
    assert_eq!(functions, count);
    for m in &matches {
        assert_ne!(
            text_at(m, "/id"),
            "fn:0x1080",
            "the query is never its own match"
        );
        assert!(int_at(m, "/shared") <= int_at(m, "/total"));
    }

    let all = call(
        &mut s,
        "func_similar",
        r#"{"target":"main","min_score":0,"limit":50}"#,
    );
    let all = list_at(data(&all), "/items/0/matches");
    assert!(all.len() > 3, "{} matches", all.len());
    let cut = int_at(&all[2], "/score");
    let strong = call(
        &mut s,
        "func_similar",
        &format!(r#"{{"target":"main","min_score":{cut},"limit":50}}"#),
    );
    let strong = list_at(data(&strong), "/items/0/matches");
    assert!(strong.len() >= 3);
    assert!(strong.iter().all(|m| int_at(m, "/score") >= cut));
    let none = call(
        &mut s,
        "func_similar",
        r#"{"target":"main","min_score":1000}"#,
    );
    assert!(
        list_at(data(&none), "/items/0/matches")
            .iter()
            .all(|m| int_at(m, "/score") == 1_000)
    );

    let over = call(&mut s, "func_similar", r#"{"target":"main","limit":51}"#);
    assert_eq!(code(&over), "LIMIT_EXCEEDED", "{over}");
    let over = call(
        &mut s,
        "func_similar",
        r#"{"target":"main","min_score":1001}"#,
    );
    assert_eq!(code(&over), "LIMIT_EXCEEDED", "{over}");
    let targets: Vec<String> = (0..21).map(|_| "\"main\"".to_owned()).collect();
    let over = call(
        &mut s,
        "func_similar",
        &format!(r#"{{"targets":[{}]}}"#, targets.join(",")),
    );
    assert_eq!(code(&over), "LIMIT_EXCEEDED", "{over}");
    let bad = call(&mut s, "func_similar", r#"{"targets":["main","0x900000"]}"#);
    let items = list_at(data(&bad), "/items");
    assert_eq!(items.len(), 2);
    assert_eq!(
        text_at(&items[1], "/error/code"),
        "ADDRESS_UNMAPPED",
        "{bad}"
    );
    assert_eq!(text_at(&items[1], "/error/field_path"), "/targets/1");
}

/// Gives every name of the functions of the open binaries.
fn binary_names(s: &ghidorah_tools::Session, ids: &[ghidorah_base::BinaryId]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for id in ids {
        let p = program(s, *id);
        for f in p.funcs() {
            if let Some(n) = p.name(f.id().0)
                && !n.is_default()
            {
                out.insert(n.text);
            }
        }
    }
    out
}

#[test]
fn hint_has_no_binary_names() {
    let (mut s, ids) = open(&[STRIPPED, FULL]);
    let mut args = proposal_args(&s, ids[0]);
    if let Value::Object(object) = &mut args
        && let Some(Value::Array(targets)) = object.get_mut("targets")
    {
        targets.push(Value::from("main"));
    }
    let envelope = call_value(&mut s, "func_similar", args.clone());
    let d = data(&envelope);
    let renames = list_at(d, "/renames");
    assert!(renames.len() >= 2, "{envelope}");
    let names = binary_names(&s, &ids);
    let calls = next_calls(&envelope);
    assert!(!calls.is_empty(), "{envelope}");
    assert_eq!(calls[0].0, "batch_run", "{envelope}");
    let hints = ghidorah_json::write(&Value::Array(
        list_at(&envelope, "/next")
            .iter()
            .map(|c| c.get("args").cloned().unwrap_or_default())
            .collect(),
    ));
    for name in &names {
        let quoted = format!("\"{name}\"");
        assert!(
            !hints.contains(&quoted),
            "the hints hold the name {name}: {hints}"
        );
    }
    let steps = list_at(&calls[0].1, "/steps");
    assert_eq!(steps.len(), 2, "{hints}");
    assert_eq!(text_at(&steps[0], "/tool"), "func_similar");
    assert_eq!(text_at(&steps[1], "/tool"), "symbol_rename");
    assert_eq!(text_at(&steps[1], "/args/items/$ref"), "s1");
    assert_eq!(text_at(&steps[1], "/args/items/ptr"), "/data/renames");
    let targets = list_at(&steps[0], "/args/targets");
    assert!(
        targets
            .iter()
            .all(|t| t.as_str().is_some_and(|t| t.starts_with("fn:"))),
        "the batch repeats the call with fn: IDs: {targets:?}"
    );
    assert_eq!(text_at(&calls[0].1, "/binary_id"), ids[0].to_string());
    assert!(
        calls.iter().any(|(tool, _)| tool == "func_get"),
        "a func_get hint on the best match: {hints}"
    );

    let (mut ro, ro_ids) = open_in(Profile::Readonly, &[STRIPPED, FULL]);
    let args = proposal_args(&ro, ro_ids[0]);
    let envelope = call_value(&mut ro, "func_similar", args);
    assert!(!list_at(data(&envelope), "/renames").is_empty());
    assert!(
        next_calls(&envelope)
            .iter()
            .all(|(tool, _)| tool != "batch_run"),
        "the readonly profile gets no rename batch: {envelope}"
    );
}
