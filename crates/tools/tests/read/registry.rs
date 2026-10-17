//! The registry-wide checks over the read tools: the lint, the agent text and the executed
//! examples with their goldens.

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::args::{globals_of, parse};
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::registry::lint;
use ghidorah_tools::{ArgKind, ArgSpec, demo, handlers};

use crate::support::{WP17B, call, demo as demo_session, json, registry, root};

#[test]
fn read_tools_lint_is_clean() {
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
fn read_tools_text_is_ste() {
    let mut texts = Vec::new();
    for tool in WP17B {
        texts.push(tool.title.to_owned());
        texts.push(tool.summary.to_owned());
        texts.push(tool.description.to_owned());
        for action in tool.actions {
            texts.push(action.line.to_owned());
        }
        for spec in tool.args.iter().chain(globals_of(tool).iter()) {
            arg_docs(spec, &mut texts);
        }
    }
    let fixed = handlers::survey::TEXTS
        .iter()
        .chain(handlers::func_list::TEXTS)
        .chain(handlers::func_sections::TEXTS)
        .chain(handlers::xref_list::TEXTS)
        .chain(handlers::search::TEXTS)
        .chain(handlers::mem_read::TEXTS);
    texts.extend(fixed.map(|t| (*t).to_owned()));
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
    let sha = ghidorah_base::hex::encode(&ghidorah_base::sha256(demo::BYTES));
    Header::new("tools_examples", "1")
        .with("fixture", demo::FIXTURE)
        .with("fixture_sha256", &sha)
}

#[test]
fn read_examples_on_demo() {
    let header = header();
    let mut count = 0;
    for tool in WP17B {
        assert!(!tool.examples.is_empty(), "{} has no example", tool.name);
        for example in tool.examples {
            let args = json(example.args);
            parse(tool, &args, None).unwrap_or_else(|e| panic!("{}: {e}", example.args));
            let mut session = demo_session();
            let envelope = call(&mut session, tool.name, example.args);
            assert_eq!(
                envelope.get("ok"),
                Some(&Value::Bool(true)),
                "{} {}: {envelope}",
                tool.name,
                example.args
            );
            let data = envelope.get("data").expect("the envelope has data");
            tool.output
                .check(data, Fit::Exact)
                .unwrap_or_else(|e| panic!("{} {}: {e}", tool.name, example.args));
            golden::assert_json(
                &root().join(example.golden),
                &header,
                &write_pretty(&envelope),
            );
            count += 1;
        }
    }
    assert!(count >= 38, "{count} examples");
}

#[test]
fn read_examples_are_deterministic() {
    for tool in WP17B {
        for example in tool.examples {
            let first = call(&mut demo_session(), tool.name, example.args);
            let second = call(&mut demo_session(), tool.name, example.args);
            assert_eq!(first, second, "{} {}", tool.name, example.args);
            let data = first.get("data").and_then(Value::as_object);
            assert!(
                data.is_some_and(|d| !d.is_empty()),
                "{} {}: {first}",
                tool.name,
                example.args
            );
        }
    }
}
