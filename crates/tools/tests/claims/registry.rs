//! The registry-wide checks over `fact_check`: the lint, the agent text and the executed
//! examples with their goldens.

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::args::{globals_of, parse};
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::registry::lint;
use ghidorah_tools::{ArgKind, ArgSpec, demo as builtin, handlers};

use crate::support::{call, json, open, registry, root};

#[test]
fn fact_check_lint_is_clean() {
    let found = lint(&registry());
    assert!(found.is_empty(), "{found:?}");
}

fn arg_docs(spec: &ArgSpec, out: &mut Vec<String>) {
    out.push(spec.doc.to_owned());
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
fn fact_check_text_is_ste() {
    let tool = &handlers::fact_check::SPEC;
    let mut texts = vec![
        tool.title.to_owned(),
        tool.summary.to_owned(),
        tool.description.to_owned(),
    ];
    for spec in tool.args.iter().chain(globals_of(tool).iter()) {
        arg_docs(spec, &mut texts);
    }
    texts.extend(handlers::fact_check::TEXTS.iter().map(|t| (*t).to_owned()));
    for row in ghidorah_analysis::facts::CATALOG {
        texts.push(row.doc.to_owned());
    }
    let mut bad = Vec::new();
    for text in &texts {
        assert!(!text.is_empty(), "an agent text is empty");
        for finding in check_agent_text(text) {
            bad.push(format!("{text}: {finding}"));
        }
    }
    assert!(bad.is_empty(), "STE findings:\n{}", bad.join("\n"));
}

/// Gives the header of the example goldens: the demo binary is the fixture of each session.
fn header() -> Header {
    let sha = ghidorah_base::hex::encode(&ghidorah_base::sha256(builtin::BYTES));
    Header::new("tools_examples", "1")
        .with("fixture", builtin::FIXTURE)
        .with("fixture_sha256", &sha)
}

/// Runs one example of `fact_check` on a new demo session.
fn run_example(args: &str) -> Value {
    let (mut s, _) = open("demo");
    call(&mut s, "fact_check", args)
}

#[test]
fn fact_check_examples_on_demo() {
    let tool = &handlers::fact_check::SPEC;
    let header = header();
    assert_eq!(tool.examples.len(), 2);
    for example in tool.examples {
        parse(tool, &json(example.args), None).unwrap_or_else(|e| panic!("{}: {e}", example.args));
        let envelope = run_example(example.args);
        assert_eq!(
            envelope.get("ok"),
            Some(&Value::Bool(true)),
            "{}: {envelope}",
            example.args
        );
        let data = envelope.get("data").expect("the envelope has data");
        tool.output
            .check(data, Fit::Exact)
            .unwrap_or_else(|e| panic!("{}: {e}", example.args));
        golden::assert_json(
            &root().join(example.golden),
            &header,
            &write_pretty(&envelope),
        );
    }
}

#[test]
fn fact_check_example_covers_each_relation() {
    let tool = &handlers::fact_check::SPEC;
    let first = tool.examples.first().expect("an example");
    let envelope = run_example(first.args);
    let verdicts = envelope
        .pointer("/data/verdicts")
        .and_then(Value::as_array)
        .expect("verdicts");
    let rels: std::collections::BTreeSet<&str> = verdicts
        .iter()
        .filter_map(|v| v.pointer("/claim/rel").and_then(Value::as_str))
        .collect();
    assert_eq!(rels.len(), 10, "{envelope}");
    let kinds: std::collections::BTreeSet<&str> = verdicts
        .iter()
        .filter_map(|v| v.get("verdict").and_then(Value::as_str))
        .collect();
    assert_eq!(kinds.len(), 3, "the example shows each verdict: {envelope}");
}

#[test]
fn fact_check_examples_are_deterministic() {
    for example in handlers::fact_check::SPEC.examples {
        assert_eq!(run_example(example.args), run_example(example.args));
    }
}
