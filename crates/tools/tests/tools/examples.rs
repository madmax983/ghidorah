//! Executed examples and argument coverage (AC-132a, AC-132b, AC-137).

use std::collections::BTreeSet;

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_tools::args::{GLOBALS, globals_of, parse};
use ghidorah_tools::{ArgKind, ArgSpec, Fit};

use crate::common::{json, root, run, walk};
use crate::test_registry::{REQUESTS, registry};

/// The keys whose values are addresses in every result.
const ADDRESS_KEYS: [&str; 14] = [
    "addr",
    "entry",
    "at",
    "from",
    "to",
    "start",
    "end",
    "va",
    "image_base",
    "stub",
    "slot",
    "file_off",
    "file_offset",
    "base",
];

/// The smallest JSON integer that a result must not hold: 2^53.
const JSON_INT_LIMIT: u64 = 1 << 53;

/// Tells if `value` is an address text `^0x[0-9a-f]+$`.
fn is_hex(value: &Value) -> bool {
    value.as_str().is_some_and(|t| {
        t.strip_prefix("0x").is_some_and(|h| {
            !h.is_empty()
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    })
}

/// Gives the problems of AC-137 in one envelope. An address-like key holds hex text, or
/// null for an address that does not exist. A `target` is a hex text, an ID or a name: a
/// number fails, and a text that starts with `0x` must be hex text.
fn hex_problems(envelope: &Value) -> Vec<String> {
    let mut out = Vec::new();
    walk(envelope, "", &mut |path, key, value| {
        if let Some(key) = key {
            let address_like = ADDRESS_KEYS.contains(&key) || key.ends_with("_addr");
            if address_like && !(is_hex(value) || value == &Value::Null) {
                out.push(format!("{path} is not hex text"));
            }
            let target = match value {
                Value::Number(_) => false,
                Value::String(text) if text.starts_with("0x") => is_hex(value),
                _ => true,
            };
            if key == "target" && !target {
                out.push(format!("{path} is not an address, an ID or a name"));
            }
        }
        if let Value::Number(n) = value {
            let small = n.as_u64().is_some_and(|v| v < JSON_INT_LIMIT)
                || n.as_i64()
                    .is_some_and(|v| v.unsigned_abs() < JSON_INT_LIMIT);
            if !small {
                out.push(format!("{path} holds the number {n}"));
            }
        }
    });
    out
}

#[test]
fn ac_132a_examples_executed() {
    let header = Header::new("tools_examples", "1");
    let mut count = 0;
    for tool in registry().tools() {
        assert!(!tool.examples.is_empty(), "{} has no example", tool.name);
        for example in tool.examples {
            let args = json(example.args);
            parse(tool, &args, None).expect("the example parses");
            let envelope = run(tool.name, example.args);
            assert_eq!(
                envelope.get("ok"),
                Some(&Value::Bool(true)),
                "{} {}: {envelope}",
                tool.name,
                example.args
            );
            let fit = if args.get("fields").is_some() {
                Fit::Partial
            } else {
                Fit::Exact
            };
            let data = envelope.get("data").expect("the envelope has data");
            if let Err(e) = tool.output.check(data, fit) {
                panic!("{} {}: {e}", tool.name, example.args);
            }
            golden::assert_json(
                &root().join(example.golden),
                &header,
                &write_pretty(&envelope),
            );
            count += 1;
        }
    }
    assert_eq!(count, 14);
}

/// Records the argument names and enum values of one call.
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

/// Gives the expected names and enum values of one spec.
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

#[test]
fn ac_132b_argument_coverage() {
    let registry = registry();
    let mut calls: Vec<(&str, &str)> = Vec::new();
    for tool in registry.tools() {
        calls.extend(tool.examples.iter().map(|e| (tool.name, e.args)));
    }
    calls.extend(REQUESTS.iter().copied());
    let (mut names, mut values) = (BTreeSet::new(), BTreeSet::new());
    for (name, args) in &calls {
        let envelope = run(name, args);
        assert_eq!(
            envelope.get("ok"),
            Some(&Value::Bool(true)),
            "{name} {args}: {envelope}"
        );
        let (_, tool) = registry.get(name).expect("a test tool");
        let globals = globals_of(tool);
        for (key, value) in json(args).as_object().expect("an object").iter() {
            if let Some(spec) = tool.arg(key) {
                record(
                    spec,
                    &format!("{name}.{key}"),
                    value,
                    &mut names,
                    &mut values,
                );
            } else if let Some(spec) = globals.iter().find(|g| g.name == key) {
                record(
                    spec,
                    &format!("global.{key}"),
                    value,
                    &mut names,
                    &mut values,
                );
            }
        }
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
fn ac_137_hex_strings() {
    for tool in registry().tools() {
        for example in tool.examples {
            let envelope = run(tool.name, example.args);
            assert_eq!(
                envelope.get("ok"),
                Some(&Value::Bool(true)),
                "{}",
                tool.name
            );
            let found = hex_problems(&envelope);
            assert!(
                found.is_empty(),
                "{} {}: {found:?}",
                tool.name,
                example.args
            );
        }
    }
    let bad =
        json(r#"{"data":{"addr":4198400,"items":[{"from":"0x40ABC"}],"n":9007199254740992}}"#);
    assert_eq!(hex_problems(&bad).len(), 3);
    // The other address keys, and a target that is a number or bad hex text.
    let bad = json(
        r#"{"data":{"image_base":4194304,"stubs":[{"stub":"4198400","slot":16384}],
        "sections":[{"file_off":4096,"base":"0x10G"}],"file_offset":12,
        "edits":[{"target":4198400},{"target":"0x40ABC"}]}}"#,
    );
    let found = hex_problems(&bad);
    assert_eq!(found.len(), 8, "{found:?}");
    // An ID, a name, a hex target and a null address pass.
    let good = json(
        r#"{"data":{"items":[{"target":"fn:0x401000"},{"target":"main"},
        {"target":"0x401000"}],"file_offset":null,"slot":"0x4000"}}"#,
    );
    assert_eq!(hex_problems(&good), Vec::<String>::new());
}
