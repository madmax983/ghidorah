//! The registry-wide checks over the read tools: the lint, the agent text and the executed
//! examples with their goldens.

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::args::{globals_of, parse};
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::registry::lint;
use ghidorah_tools::{ArgKind, ArgSpec, Host, Session, budget, demo, handlers};

use crate::support::{WP17B, call, demo as demo_session, json, registry, root};

#[test]
fn read_tools_lint_is_clean() {
    let found = lint(&registry());
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn shipped_registry_holds_the_read_tools() {
    let shipped = <Session as Host>::registry();
    assert_eq!(shipped.names(), registry().names());
    for tool in WP17B {
        assert!(
            shipped.get(tool.name).is_some(),
            "{} is not shipped",
            tool.name
        );
    }
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

#[test]
fn regress_tool_max_chars_defaults() {
    // The defaults of design Section 10.9: 16,000 for list tools, 24,000 for the four large
    // tools, 12,000 for binary_survey and 8,000 for all other tools.
    let large = ["func_get", "batch_run", "fact_check", "func_similar"];
    let shipped = <Session as Host>::registry();
    let mut lists = Vec::new();
    for tool in shipped.tools() {
        let want = if tool.list.is_some() {
            lists.push(tool.name);
            16_000
        } else if large.contains(&tool.name) {
            24_000
        } else if tool.name == "binary_survey" {
            12_000
        } else {
            8_000
        };
        assert_eq!(tool.max_chars, want, "{}", tool.name);
    }
    lists.sort_unstable();
    assert_eq!(
        lists,
        [
            "func_list",
            "history_list",
            "search",
            "tool_search",
            "xref_list"
        ]
    );
    assert_eq!(
        [
            budget::LIST_MAX_CHARS,
            budget::LARGE_MAX_CHARS,
            budget::SURVEY_MAX_CHARS,
            budget::OTHER_MAX_CHARS,
        ],
        [16_000, 24_000, 12_000, 8_000]
    );
    // The why tree defaults of fact_check come from the explain module of the analysis crate.
    let default = |name: &str| handlers::fact_check::SPEC.arg(name).and_then(|a| a.default);
    let depth = ghidorah_analysis::facts::explain::DEFAULT_DEPTH.to_string();
    let nodes = ghidorah_analysis::facts::explain::DEFAULT_NODES.to_string();
    assert_eq!(default("depth"), Some(depth.as_str()));
    assert_eq!(default("max_nodes"), Some(nodes.as_str()));
    assert_eq!(
        (default("depth"), default("max_nodes")),
        (Some("3"), Some("200"))
    );
}
