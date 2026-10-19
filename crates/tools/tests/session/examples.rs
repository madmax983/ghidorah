//! The executed examples, the registry lint and the agent text of the WP-13b tools.

use ghidorah_base::{Address, BinaryId};
use ghidorah_db::{Edit, SymKind};
use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::args::{globals_of, parse};
use ghidorah_tools::outshape::Fit;
use ghidorah_tools::registry::lint;
use ghidorah_tools::session::LabelRule;
use ghidorah_tools::{ArgKind, ArgSpec, Session, ToolError, demo, handlers, instructions};

use crate::support::{
    DEMO_ID, call, config, demo as demo_session, json, registry, root, session_with,
};

/// The tools whose examples need one committed edit in the session `mcp-1`.
const NEEDS_EDIT: &[&str] = &["history_list", "history_undo"];

/// The tools whose examples need the facts of the analysis engine: the read tools of WP-17b
/// and the memory tools of WP-22a. The override and type tools of WP-22b, the claim tool of
/// WP-24 and the batch tool of WP-25 also need them. The similarity tool of WP-29 needs them.
const NEEDS_ANALYSIS: &[&str] = &[
    "binary_survey",
    "func_list",
    "func_get",
    "xref_list",
    "search",
    "mem_read",
    "addr_info",
    "fact_check",
    "type_get",
    "session_brief",
    "symbol_rename",
    "comment_set",
    "note_write",
    "func_edit",
    "type_edit",
    "batch_run",
    "func_similar",
];

/// Gives the session of the examples of `tool`: the demo binary. A read, claim, memory,
/// override, type or batch tool gets the analysis engine, as in the tests that own its
/// goldens. A history tool
/// gets one rename in the session `mcp-1`, so `history_undo` has a transaction to undo.
fn example_session(tool: &str) -> Session {
    if NEEDS_ANALYSIS.contains(&tool) {
        let mut session = session_with(config());
        handlers::analysis_run::install(&mut session);
        let envelope = call(&mut session, "binary_load", r#"{"builtin":"demo"}"#);
        assert_eq!(
            envelope.pointer("/data/binary_id").and_then(Value::as_str),
            Some(DEMO_ID),
            "{envelope}"
        );
        return session;
    }
    if !NEEDS_EDIT.contains(&tool) {
        return demo_session();
    }
    let mut cfg = config();
    cfg.labels = LabelRule::Mcp;
    let mut session = session_with(cfg);
    let envelope = call(&mut session, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(
        envelope.pointer("/data/binary_id").and_then(Value::as_str),
        Some(DEMO_ID),
        "{envelope}"
    );
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    session
        .transact(id, "symbol_rename", "mcp-1", |tx| {
            let fact = tx.fact("read_input".to_owned());
            tx.apply(Edit::SetName {
                addr: Address::ram(0x1090),
                key: None,
                kind: SymKind::Label,
                primary: true,
                name: Some(fact),
                evidence: vec!["fn:0x1080".to_owned()],
            })
            .map(drop)
            .map_err(|e| ToolError::new(e.code()))
        })
        .expect("the rename commits");
    session
}

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
            let mut session = example_session(tool.name);
            if let Some(setup) = handlers::func_edit::setup_of(example.args) {
                let envelope = call(&mut session, tool.name, setup);
                assert_eq!(
                    envelope.get("ok"),
                    Some(&Value::Bool(true)),
                    "the setup {setup} fails: {envelope}"
                );
            }
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
        .chain(handlers::analysis_run::TEXTS)
        .chain(handlers::calc::TEXTS)
        .chain(handlers::history_list::TEXTS)
        .chain(handlers::tool_search::TEXTS)
        .chain(handlers::history_undo::TEXTS)
        .chain(handlers::survey::TEXTS)
        .chain(handlers::func_list::TEXTS)
        .chain(handlers::func_sections::TEXTS)
        .chain(handlers::xref_list::TEXTS)
        .chain(handlers::search::TEXTS)
        .chain(handlers::mem_read::TEXTS)
        .chain(handlers::symbol_rename::TEXTS)
        .chain(handlers::comment_set::TEXTS)
        .chain(handlers::note_write::TEXTS)
        .chain(handlers::session_brief::TEXTS)
        .chain(handlers::func_edit::TEXTS)
        .chain(handlers::type_get::TEXTS)
        .chain(handlers::type_edit::TEXTS)
        .chain(handlers::fact_check::TEXTS)
        .chain(handlers::batch_run::TEXTS)
        .chain(&[ghidorah_tools::session::WHY_REOPEN]);
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
