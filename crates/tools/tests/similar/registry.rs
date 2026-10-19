//! The registry-wide checks over `func_similar`: the lint, the agent text, the profiles and the
//! executed examples with their goldens.

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::args::{globals_of, parse};
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::registry::lint;
use ghidorah_tools::{ArgKind, ArgSpec, Host, Profile, demo as builtin, handlers};

use crate::support::{call, json, registry, root, session_in};

#[test]
fn func_similar_lint_is_clean() {
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
fn func_similar_text_is_ste() {
    let tool = &handlers::func_similar::SPEC;
    let mut texts = vec![
        tool.title.to_owned(),
        tool.summary.to_owned(),
        tool.description.to_owned(),
    ];
    for spec in tool.args.iter().chain(globals_of(tool).iter()) {
        arg_docs(spec, &mut texts);
    }
    texts.extend(
        handlers::func_similar::TEXTS
            .iter()
            .map(|t| (*t).to_owned()),
    );
    let mut bad = Vec::new();
    for text in &texts {
        assert!(!text.is_empty(), "an agent text is empty");
        for finding in check_agent_text(text) {
            bad.push(format!("{text}: {finding}"));
        }
    }
    assert!(bad.is_empty(), "STE findings:\n{}", bad.join("\n"));
}

#[test]
fn func_similar_profiles() {
    let tool = &handlers::func_similar::SPEC;
    assert_eq!(tool.profiles, [Profile::Full, Profile::Readonly]);
    assert!(tool.annotations.read_only, "a read-only tool");
    assert!(tool.annotations.idempotent);
    assert!(!tool.annotations.destructive);
    for profile in [Profile::Full, Profile::Readonly] {
        let s = session_in(profile);
        assert!(s.in_profile("func_similar"), "{profile:?}");
    }
    assert!(!session_in(Profile::Mini).in_profile("func_similar"));
}

/// Gives the header of the example goldens: the demo binary is the fixture of each session.
fn header() -> Header {
    let sha = ghidorah_base::hex::encode(&ghidorah_base::sha256(builtin::BYTES));
    Header::new("tools_examples", "1")
        .with("fixture", builtin::FIXTURE)
        .with("fixture_sha256", &sha)
}

/// Runs one example of `func_similar` on a new demo session.
fn run_example(args: &str) -> Value {
    let mut s = session_in(Profile::Full);
    let load = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(load.get("ok"), Some(&Value::Bool(true)), "{load}");
    call(&mut s, "func_similar", args)
}

#[test]
fn func_similar_examples_on_demo() {
    let tool = &handlers::func_similar::SPEC;
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
        let matches = data
            .pointer("/items/0/matches")
            .and_then(Value::as_array)
            .map_or(0, <[Value]>::len);
        assert!(matches > 0, "the example shows matches: {envelope}");
        golden::assert_json(
            &root().join(example.golden),
            &header,
            &write_pretty(&envelope),
        );
    }
}

#[test]
fn func_similar_examples_are_deterministic() {
    for example in handlers::func_similar::SPEC.examples {
        assert_eq!(run_example(example.args), run_example(example.args));
    }
}

#[test]
fn tool_search_finds_func_similar() {
    let mut s = session_in(Profile::Full);
    for query in [
        "similar functions",
        "clone",
        "bsim",
        "a clone of a function",
    ] {
        let envelope = call(&mut s, "tool_search", &format!(r#"{{"query":"{query}"}}"#));
        let first = envelope
            .pointer("/data/items/0/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert_eq!(first, "func_similar", "{query}: {envelope}");
    }
    let mini = session_in(Profile::Mini);
    assert!(
        !mini.in_profile("func_similar"),
        "mini keeps its cap of 10 tools"
    );
}
