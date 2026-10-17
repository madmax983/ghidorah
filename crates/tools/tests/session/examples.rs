//! The executed examples, the registry lint and the agent text of the WP-13b tools.

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::args::{globals_of, parse};
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::registry::lint;
use ghidorah_tools::{ArgKind, ArgSpec, demo, handlers, instructions};

use crate::support::{call, demo as demo_session, json, registry, root};

/// Gives the header of the example goldens: the demo binary is the fixture of each session.
fn header() -> Header {
    let sha = ghidorah_base::hex::encode(&ghidorah_base::sha256(demo::BYTES));
    Header::new("tools_examples", "1")
        .with("fixture", demo::FIXTURE)
        .with("fixture_sha256", &sha)
}

#[test]
fn examples_on_demo() {
    let header = header();
    let mut count = 0;
    for tool in registry().tools() {
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
            let fit = if args.get("fields").is_some() {
                Fit::Partial
            } else {
                Fit::Exact
            };
            let data = envelope.get("data").expect("the envelope has data");
            tool.output
                .check(data, fit)
                .unwrap_or_else(|e| panic!("{} {}: {e}", tool.name, example.args));
            golden::assert_json(
                &root().join(example.golden),
                &header,
                &write_pretty(&envelope),
            );
            count += 1;
        }
    }
    assert!(count >= 12, "{count} examples");
}

#[test]
fn registry_lint_is_clean() {
    let found = lint(&registry());
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
fn agent_text_is_ste() {
    let mut texts: Vec<(String, String)> = Vec::new();
    for tool in registry().tools() {
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
    let handler_texts = handlers::load::TEXTS
        .iter()
        .chain(handlers::calc::TEXTS)
        .chain(handlers::tool_search::TEXTS);
    for text in handler_texts {
        texts.push(("handler text".to_owned(), (*text).to_owned()));
    }
    for line in instructions::LINES {
        texts.push(("instruction".to_owned(), line.text.to_owned()));
    }
    texts.push(("instruction".to_owned(), instructions::first_line()));
    assert!(texts.len() > 30, "{} texts", texts.len());
    let mut bad = Vec::new();
    for (place, text) in &texts {
        assert!(!text.is_empty(), "{place} is empty");
        for finding in check_agent_text(text) {
            bad.push(format!("{place}: {finding}"));
        }
    }
    assert!(bad.is_empty(), "STE findings:\n{}", bad.join("\n"));
}
