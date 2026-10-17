//! The registry-wide checks over the shipped tools and the history tools: the lint, the agent
//! text and the executed examples.

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::args::{globals_of, parse};
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::registry::lint;
use ghidorah_tools::{ArgKind, ArgSpec, Registry, demo, handlers};

use crate::support::{CATALOG, call, config, json, load_demo, rename, root, session_with};

#[test]
fn catalog_lint_is_clean() {
    let found = lint(&Registry::new(CATALOG));
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
fn history_tools_text_is_ste() {
    let mut texts = Vec::new();
    for tool in [&handlers::history_list::SPEC, &handlers::history_undo::SPEC] {
        texts.push(tool.title.to_owned());
        texts.push(tool.summary.to_owned());
        texts.push(tool.description.to_owned());
        for spec in tool.args.iter().chain(globals_of(tool).iter()) {
            arg_docs(spec, &mut texts);
        }
    }
    let fixed = handlers::history_list::TEXTS
        .iter()
        .chain(handlers::history_undo::TEXTS);
    texts.extend(fixed.map(|t| (*t).to_owned()));
    texts.push(ghidorah_tools::session::WHY_REOPEN.to_owned());
    let mut bad = Vec::new();
    for text in &texts {
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

/// Runs the examples of the history tools. Each session has the demo binary and one rename,
/// so `history_undo` has a transaction to undo.
#[test]
fn history_examples_on_demo() {
    let header = header();
    let mut count = 0;
    for tool in [&handlers::history_list::SPEC, &handlers::history_undo::SPEC] {
        for example in tool.examples {
            let args = json(example.args);
            parse(tool, &args, None).unwrap_or_else(|e| panic!("{}: {e}", example.args));
            let mut session = session_with(config());
            let id = load_demo(&mut session);
            rename(&mut session, id, "mcp-1", 0x1090, "read_input");
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
    assert_eq!(count, 4);
}
