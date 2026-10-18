//! The registry-wide rules over the full registry: the shipped tools and `batch_run`
//! (AC-024, AC-129a to AC-129f, AC-130a, AC-131a, AC-131b, AC-132a, AC-132b, AC-137,
//! AC-143, AC-221, AC-222).
//!
//! The tests of WP-13a and WP-13b check these rules on their registries. These tests check
//! them on every tool of the catalog that this branch holds.

use std::collections::BTreeSet;
use std::path::Path;

use ghidorah_json::Value;
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::args::{GLOBALS, globals_of, parse};
use ghidorah_tools::hints::{MAX_NEXT, check};
use ghidorah_tools::profiles::{MAX_FULL, MAX_FULL_CHARS, MAX_MINI, MAX_MINI_CHARS};
use ghidorah_tools::registry::lint;
use ghidorah_tools::{
    ArgKind, ArgSpec, Fit, Profile, ProfileSet, Registry, Session, ToolSpec, handlers,
};

use crate::support::{call, call_value, chars, demo, full_registry, json, root, text_at};

/// The characters that the catalog keeps free for the tools of later WPs: `fact_check` and
/// `func_similar` when they are not in the registry yet.
const LATER_TOOL_CHARS: u64 = 1_200;

/// Gives the `tools/list` size of `profile` over `registry`.
fn catalog_chars(registry: &Registry<Session>, profile: Profile) -> u64 {
    let list = ProfileSet::new(profile, None).tools_list(registry);
    chars(&Value::object([("tools", list)]))
}

#[test]
fn ac_131a_full_catalog_headroom() {
    let registry = full_registry();
    let later = ["fact_check", "func_similar"]
        .iter()
        .filter(|t| registry.get(t).is_none())
        .count() as u64;
    let size = catalog_chars(&registry, Profile::Full);
    assert!(
        size + later * LATER_TOOL_CHARS <= MAX_FULL_CHARS as u64,
        "{size} characters and {later} later tools"
    );
    assert!(registry.tools().len() <= MAX_FULL);
}

#[test]
fn ac_131b_mini_catalog_with_batch_run() {
    let registry = full_registry();
    let set = ProfileSet::new(Profile::Mini, None);
    let names: Vec<&str> = set.tools(&registry).iter().map(|t| t.name).collect();
    assert!(names.contains(&"batch_run"), "{names:?}");
    assert!(names.len() <= MAX_MINI);
    let size = catalog_chars(&registry, Profile::Mini);
    assert!(size <= MAX_MINI_CHARS as u64, "{size} characters");
}

#[test]
fn ac_129_full_registry_lint() {
    let found = lint(&full_registry());
    assert!(found.is_empty(), "{found:?}");
}

fn arg_docs(spec: &ArgSpec, out: &mut Vec<(String, String)>) {
    out.push((format!("argument {}", spec.name), spec.doc.to_owned()));
    match spec.kind {
        ArgKind::Obj(members) => {
            for m in members {
                arg_docs(m, out);
            }
        }
        ArgKind::List(item, _) => arg_docs(item, out),
        _ => {}
    }
}

#[test]
fn ac_024_full_registry_text() {
    let mut texts: Vec<(String, String)> = Vec::new();
    for tool in full_registry().tools() {
        texts.push((format!("{} summary", tool.name), tool.summary.to_owned()));
        texts.push((
            format!("{} description", tool.name),
            tool.description.to_owned(),
        ));
        for action in tool.actions {
            texts.push((format!("{} action", tool.name), action.line.to_owned()));
        }
        for spec in tool.args.iter().chain(globals_of(tool).iter()) {
            arg_docs(spec, &mut texts);
        }
    }
    for text in handlers::batch_run::TEXTS {
        texts.push(("batch text".to_owned(), (*text).to_owned()));
    }
    for topic in ghidorah_tools::tool_search::TOPICS {
        texts.push((format!("topic {}", topic.name), topic.text.to_owned()));
    }
    let mut bad = Vec::new();
    for (place, text) in &texts {
        assert!(!text.is_empty(), "{place} is empty");
        for finding in check_agent_text(text) {
            bad.push(format!("{place}: {finding}"));
        }
    }
    assert!(bad.is_empty(), "STE findings:\n{}", bad.join("\n"));
}

/// The tools whose examples need a committed edit of the session first.
const NEEDS_EDIT: [&str; 2] = ["history_list", "history_undo"];

/// Gives the envelope of each example of the full registry on the analyzed demo:
/// `(tool, args, envelope)`.
fn example_envelopes() -> Vec<(&'static ToolSpec<Session>, &'static str, Value)> {
    let mut out = Vec::new();
    for tool in full_registry().tools() {
        for example in tool.examples {
            let mut s = demo();
            if NEEDS_EDIT.contains(&tool.name) {
                let rename = call(
                    &mut s,
                    "symbol_rename",
                    r#"{"target":"0x1090","name":"read_input"}"#,
                );
                assert_eq!(rename.get("ok"), Some(&Value::Bool(true)), "{rename}");
            }
            if let Some(setup) = handlers::func_edit::setup_of(example.args) {
                let envelope = call(&mut s, tool.name, setup);
                assert_eq!(envelope.get("ok"), Some(&Value::Bool(true)), "{envelope}");
            }
            let envelope = call(&mut s, tool.name, example.args);
            out.push((*tool, example.args, envelope));
        }
    }
    out
}

/// The keys whose values are addresses in every result.
const ADDRESS_KEYS: [&str; 8] = ["addr", "entry", "at", "from", "to", "start", "end", "va"];

/// Calls `f` for each object member of `value` with its key.
fn walk(value: &Value, f: &mut dyn FnMut(&str, &Value)) {
    match value {
        Value::Object(object) => {
            for (key, member) in object.iter() {
                f(key, member);
                walk(member, f);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, f);
            }
        }
        _ => {}
    }
}

/// Gives the problems of the hints of one envelope (AC-143).
fn hint_problems(registry: &Registry<Session>, envelope: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let all = |_: &str| true;
    let mut lists = vec![envelope.get("next").cloned().unwrap_or_default()];
    if let Some(entries) = envelope.pointer("/data/steps").and_then(Value::as_array) {
        lists.extend(entries.iter().filter_map(|e| e.get("next").cloned()));
    }
    for list in lists {
        let calls = list.as_array().unwrap_or_default();
        if calls.len() > MAX_NEXT {
            out.push(format!("{} next calls", calls.len()));
        }
        for c in calls {
            let call = ghidorah_tools::Call::new(
                &text_at(c, "/tool"),
                c.get("args").cloned().unwrap_or_default(),
                &text_at(c, "/why"),
            );
            if let Err(e) = check(registry, &all, &call) {
                out.push(format!("{c}: {e}"));
            }
        }
    }
    out
}

#[test]
fn ac_132a_137_143_full_registry_examples() {
    let registry = full_registry();
    let envelopes = example_envelopes();
    assert!(envelopes.len() >= 60, "{} examples", envelopes.len());
    for (tool, args, envelope) in &envelopes {
        assert_eq!(
            envelope.get("ok"),
            Some(&Value::Bool(true)),
            "{} {args}: {envelope}",
            tool.name
        );
        parse(tool, &json(args), None).unwrap_or_else(|e| panic!("{args}: {e}"));
        let fit = if json(args).get("fields").is_some() {
            Fit::Partial
        } else {
            Fit::Exact
        };
        let data = envelope.get("data").expect("data");
        tool.output
            .check(data, fit)
            .unwrap_or_else(|e| panic!("{} {args}: {e}", tool.name));
        let mut bad = Vec::new();
        walk(envelope, &mut |key, value| {
            let address = ADDRESS_KEYS.contains(&key) || key.ends_with("_addr");
            let hex = |v: &Value| {
                v.as_str()
                    .is_some_and(ghidorah_tools::outshape::is_addr_text)
            };
            let ok = match value {
                Value::Array(items) => items.iter().all(hex),
                other => hex(other),
            };
            if address && !ok {
                bad.push(format!("{key} = {value}"));
            }
            if let Value::Number(n) = value {
                let small = n.as_u64().is_some_and(|v| v < 1 << 53)
                    || n.as_i64().is_some_and(|v| v.unsigned_abs() < 1 << 53);
                if !small {
                    bad.push(format!("{key} = {n}"));
                }
            }
        });
        assert!(bad.is_empty(), "AC-137 {} {args}: {bad:?}", tool.name);
        let hints = hint_problems(&registry, envelope);
        assert!(hints.is_empty(), "AC-143 {} {args}: {hints:?}", tool.name);
    }
}

/// Records the argument paths and enum values of one call.
fn record(
    spec: &ArgSpec,
    path: &str,
    value: &Value,
    names: &mut BTreeSet<String>,
    values: &mut BTreeSet<String>,
) {
    names.insert(path.to_owned());
    match (spec.kind, value) {
        (ArgKind::Enum(_), Value::String(v)) => {
            values.insert(format!("{path}={v}"));
        }
        (ArgKind::Obj(members), Value::Object(object)) => {
            for (key, member) in object.iter() {
                if let Some(m) = members.iter().find(|m| m.name == key) {
                    record(m, &format!("{path}.{key}"), member, names, values);
                }
            }
        }
        (ArgKind::List(item, _), Value::Array(items)) => {
            for v in items {
                record(item, &format!("{path}[]"), v, names, values);
            }
        }
        _ => {}
    }
}

/// Gives the expected argument paths and enum values of one spec.
fn expect(spec: &ArgSpec, path: &str, names: &mut BTreeSet<String>, values: &mut BTreeSet<String>) {
    names.insert(path.to_owned());
    match spec.kind {
        ArgKind::Enum(all) => {
            for v in all {
                values.insert(format!("{path}={v}"));
            }
        }
        ArgKind::Obj(members) => {
            for m in members {
                expect(m, &format!("{path}.{}", m.name), names, values);
            }
        }
        ArgKind::List(item, _) => expect(item, &format!("{path}[]"), names, values),
        _ => {}
    }
}

/// One request of `tests/data/requests/*.jsonl`: `{ tool, args, before? }`.
struct Line {
    tool: String,
    args: Value,
    before: Vec<(String, Value)>,
}

/// Gives the requests of `tests/data/requests/*.jsonl`.
fn requests() -> Vec<Line> {
    let dir = root().join("tests/data/requests");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("the request file reads");
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let value = json(line);
            let before = value
                .get("before")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .map(|c| {
                    (
                        text_at(c, "/tool"),
                        c.get("args").cloned().unwrap_or_default(),
                    )
                })
                .collect();
            out.push(Line {
                tool: text_at(&value, "/tool"),
                args: value.get("args").cloned().unwrap_or_default(),
                before,
            });
        }
    }
    out
}

/// Gives the name of the request file directory, for messages.
fn requests_dir() -> &'static Path {
    Path::new("tests/data/requests")
}

/// Records the argument paths and enum values of one call of `name`. The steps of a batch
/// count as calls of their tools.
fn record_call(
    registry: &Registry<Session>,
    name: &str,
    args: &Value,
    names: &mut BTreeSet<String>,
    values: &mut BTreeSet<String>,
) {
    let (_, tool) = registry
        .get(name)
        .unwrap_or_else(|| panic!("{name} is not a tool"));
    let globals = globals_of(tool);
    for (key, value) in args
        .as_object()
        .unwrap_or(&ghidorah_json::Object::new())
        .iter()
    {
        if let Some(spec) = tool.arg(key) {
            record(spec, &format!("{name}.{key}"), value, names, values);
        } else if let Some(spec) = globals.iter().find(|g| g.name == key) {
            record(spec, &format!("global.{key}"), value, names, values);
        }
    }
    if name == "batch_run" {
        let steps = args
            .get("steps")
            .and_then(Value::as_array)
            .unwrap_or_default();
        for step in steps {
            let tool = text_at(step, "/tool");
            if registry.get(&tool).is_some() {
                let empty = Value::Object(ghidorah_json::Object::new());
                record_call(
                    registry,
                    &tool,
                    step.get("args").unwrap_or(&empty),
                    names,
                    values,
                );
            }
        }
    }
}

#[test]
fn ac_132b_full_argument_coverage() {
    let registry = full_registry();
    let (mut names, mut values) = (BTreeSet::new(), BTreeSet::new());
    for tool in registry.tools() {
        for example in tool.examples {
            record_call(
                &registry,
                tool.name,
                &json(example.args),
                &mut names,
                &mut values,
            );
        }
    }
    for line in requests() {
        let mut s = demo();
        for (tool, args) in &line.before {
            let envelope = call_value(&mut s, tool, args.clone());
            assert_eq!(
                envelope.get("ok"),
                Some(&Value::Bool(true)),
                "{}: before {tool} {args}: {envelope}",
                requests_dir().display()
            );
        }
        let envelope = call_value(&mut s, &line.tool, line.args.clone());
        assert_eq!(
            envelope.get("ok"),
            Some(&Value::Bool(true)),
            "{}: {} {}: {envelope}",
            requests_dir().display(),
            line.tool,
            line.args
        );
        for entry in envelope
            .pointer("/data/steps")
            .and_then(Value::as_array)
            .unwrap_or_default()
        {
            assert_eq!(
                entry.get("ok"),
                Some(&Value::Bool(true)),
                "{}: {}: {entry}",
                requests_dir().display(),
                line.args
            );
        }
        record_call(&registry, &line.tool, &line.args, &mut names, &mut values);
    }
    let (mut want_names, mut want_values) = (BTreeSet::new(), BTreeSet::new());
    for tool in registry.tools() {
        for spec in tool.args {
            expect(
                spec,
                &format!("{}.{}", tool.name, spec.name),
                &mut want_names,
                &mut want_values,
            );
        }
    }
    for spec in &GLOBALS {
        expect(
            spec,
            &format!("global.{}", spec.name),
            &mut want_names,
            &mut want_values,
        );
    }
    let missing: Vec<&String> = want_names.difference(&names).collect();
    assert!(missing.is_empty(), "arguments with no call: {missing:?}");
    let missing: Vec<&String> = want_values.difference(&values).collect();
    assert!(missing.is_empty(), "enum values with no call: {missing:?}");
}

#[test]
fn ac_221_full_selector_rules() {
    let registry = full_registry();
    let mut checked = 0;
    for tool in registry.tools() {
        let Some(selector) = tool.selector() else {
            continue;
        };
        for action in tool.actions {
            let example = json(action.example);
            for spec in tool.args {
                let required = spec
                    .required_when
                    .iter()
                    .any(|(s, v)| *s == selector.name && *v == action.value);
                if required && example.get(spec.name).is_some() {
                    let mut args = example.as_object().cloned().unwrap_or_default();
                    let _ = args.remove(spec.name);
                    let mut s = demo();
                    let envelope = call_value(&mut s, tool.name, Value::Object(args));
                    assert_eq!(
                        text_at(&envelope, "/error/code"),
                        "MISSING_ARGUMENT",
                        "{} {} without {}: {envelope}",
                        tool.name,
                        action.value,
                        spec.name
                    );
                    assert_eq!(text_at(&envelope, "/error/details/action"), action.value);
                    checked += 1;
                }
                let forbidden = spec
                    .forbidden_when
                    .iter()
                    .any(|(s, v)| *s == selector.name && *v == action.value);
                if forbidden {
                    let mut args = example.as_object().cloned().unwrap_or_default();
                    let sample = match spec.kind {
                        ArgKind::Bool => Value::Bool(true),
                        ArgKind::Addr | ArgKind::Str(_) => Value::from("0x1080"),
                        _ => continue,
                    };
                    args.push(spec.name, sample);
                    let mut s = demo();
                    let envelope = call_value(&mut s, tool.name, Value::Object(args));
                    assert_eq!(
                        text_at(&envelope, "/error/code"),
                        "INVALID_ARGUMENT",
                        "{} {} with {}: {envelope}",
                        tool.name,
                        action.value,
                        spec.name
                    );
                    assert_eq!(text_at(&envelope, "/error/details/action"), action.value);
                    checked += 1;
                }
            }
        }
    }
    assert!(checked >= 8, "{checked} rules");
}
