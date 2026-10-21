//! The code triggers of `tests/data/code_triggers.jsonl` (AC-141b, AC-220) and the agent text
//! of their envelopes (AC-024, AC-142, AC-143).
//!
//! The line reader, the setups and the runner are in `tests/support/triggers.rs`.

use std::collections::BTreeSet;

use ghidorah_base::catalog::RepairClass;
use ghidorah_base::{ErrorCode, WarningCode};
use ghidorah_json::Value;
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::Host;
use ghidorah_tools::hints::{MAX_NEXT, check};

use crate::support::{call, call_value, json, text_at};
use crate::trigger_lines::{Keep, holds_code, lines, run, setup};

/// Gives the codes of both enums that the lines must cover.
fn wanted() -> BTreeSet<String> {
    let mut out: BTreeSet<String> = ErrorCode::ALL
        .iter()
        .map(|c| c.info().name.to_owned())
        .collect();
    out.extend(WarningCode::ALL.iter().map(|c| c.info().name.to_owned()));
    out
}

#[test]
fn ac_141b_code_triggers() {
    let all = lines();
    assert!(all.len() >= 40, "{} lines", all.len());
    let mut bad = Vec::new();
    for line in &all {
        let (_s, envelope, _keep) = run(line);
        if !holds_code(&envelope, &line.code) {
            bad.push(format!("line {} ({}): {envelope}", line.number, line.code));
        }
    }
    assert!(
        bad.is_empty(),
        "lines without their code:\n{}",
        bad.join("\n")
    );
    let covered: BTreeSet<String> = all.into_iter().map(|l| l.code).collect();
    let missing: Vec<String> = wanted().difference(&covered).cloned().collect();
    assert!(missing.is_empty(), "codes with no line: {missing:?}");
}

#[test]
fn selfcheck_ok_has_no_warning() {
    let mut keep = Keep::new();
    let mut s = setup("selfcheck", &mut keep);
    let real = call(&mut s, "selfcheck_tool", r#"{"wrong":false}"#);
    assert_eq!(text_at(&real, "/data/validation"), "ok", "{real}");
    assert!(!holds_code(&real, "W_STRUCTURE_SELFCHECK"), "{real}");
    let wrong = call(&mut s, "selfcheck_tool", r#"{"wrong":true}"#);
    assert_eq!(text_at(&wrong, "/data/validation"), "repaired", "{wrong}");
    let mut demo = crate::support::demo();
    let list = call(&mut demo, "func_list", r#"{"limit":1000}"#);
    let ids: Vec<String> = list
        .pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|f| text_at(f, "/id"))
        .collect();
    assert!(ids.len() > 5, "{list}");
    for id in ids {
        let args = Value::object([
            ("target", Value::from(id.as_str())),
            ("include", json(r#"["decomp"]"#)),
        ]);
        let envelope = call_value(&mut demo, "func_get", args);
        assert!(
            !holds_code(&envelope, "W_STRUCTURE_SELFCHECK"),
            "{id}: {envelope}"
        );
        let validation = text_at(&envelope, "/data/decomp/metrics/validation/structure");
        assert_eq!(validation, "ok", "{id}: {envelope}");
    }
}

/// Tells if `code` names an error code of class R, or of class R* with a repair call.
fn repair_code(code: &str) -> Option<RepairClass> {
    ErrorCode::ALL
        .iter()
        .find(|c| c.info().name == code)
        .map(|c| c.info().class)
        .filter(|class| matches!(class, RepairClass::Repair | RepairClass::RepairWhen))
}

#[test]
fn ac_220_repair_calls() {
    let mut checked = 0;
    for line in lines() {
        let Some(class) = repair_code(&line.code) else {
            continue;
        };
        let (mut s, envelope, _keep) = run(&line);
        let next = envelope.pointer("/next/0").cloned();
        let Some(next) = next else {
            assert_eq!(
                class,
                RepairClass::RepairWhen,
                "line {} ({}) has no next[0]: {envelope}",
                line.number,
                line.code
            );
            continue;
        };
        let tool = text_at(&next, "/tool");
        let args = next.get("args").cloned().unwrap_or_default();
        let registry = s.active_registry();
        let call = ghidorah_tools::Call::new(&tool, args.clone(), "");
        let in_profile = |name: &str| s.in_profile(name);
        check(&registry, &in_profile, &call)
            .unwrap_or_else(|e| panic!("line {}: {e}: {next}", line.number));
        let repaired = call_value(&mut s, &tool, args);
        assert!(
            !holds_code(&repaired, &line.code),
            "line {} ({}): next[0] does not repair: {repaired}",
            line.number,
            line.code
        );
        checked += 1;
    }
    assert!(checked >= 8, "{checked} repairs");
}

/// Gives every text member of the error, the warnings and the steps of an envelope.
fn agent_texts(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, member) in object.iter() {
                if matches!(key, "message" | "hint" | "why")
                    && let Some(text) = member.as_str()
                {
                    out.push(text.to_owned());
                }
                agent_texts(member, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| agent_texts(i, out)),
        _ => {}
    }
}

#[test]
fn trigger_envelopes_have_clean_text_and_hints() {
    for line in lines() {
        let (s, envelope, _keep) = run(&line);
        let mut texts = Vec::new();
        agent_texts(&envelope, &mut texts);
        for text in texts {
            for bad in ["Some(", "Os {", "Error {", "panicked at"] {
                assert!(!text.contains(bad), "line {}: {text}", line.number);
            }
            let found = check_agent_text(&text);
            assert!(found.is_empty(), "line {}: {text}: {found:?}", line.number);
        }
        let next = envelope
            .get("next")
            .and_then(Value::as_array)
            .unwrap_or_default();
        assert!(next.len() <= MAX_NEXT);
        let registry = s.active_registry();
        let in_profile = |name: &str| s.in_profile(name);
        for c in next {
            let call = ghidorah_tools::Call::new(
                &text_at(c, "/tool"),
                c.get("args").cloned().unwrap_or_default(),
                "",
            );
            check(&registry, &in_profile, &call)
                .unwrap_or_else(|e| panic!("line {}: {e}: {c}", line.number));
        }
    }
}
