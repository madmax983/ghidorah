//! Agent-facing text passes the STE checker in deny mode (AC-024).

use ghidorah_base::{ErrorCode, WarningCode};
use ghidorah_testkit::ste::check_agent_text;
use ghidorah_tools::args::globals_of;
use ghidorah_tools::registry::shipped;
use ghidorah_tools::{ArgKind, ArgSpec, Registry, ToolError};

use crate::test_registry::registry;

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

/// Adds the agent text of each tool of `registry`: summaries, descriptions, action lines and
/// argument docs.
fn tool_texts<S: 'static>(registry: &Registry<S>, out: &mut Vec<(String, String)>) {
    for tool in registry.tools() {
        out.push((format!("{} summary", tool.name), tool.summary.to_owned()));
        out.push((
            format!("{} description", tool.name),
            tool.description.to_owned(),
        ));
        for action in tool.actions {
            out.push((
                format!("{} action {}", tool.name, action.value),
                action.line.to_owned(),
            ));
        }
        for spec in tool.args {
            arg_docs(spec, out);
        }
        for spec in &globals_of(tool) {
            arg_docs(spec, out);
        }
    }
}

#[test]
fn ac_024_ste_agent_text() {
    let mut texts: Vec<(String, String)> = Vec::new();
    tool_texts(&registry(), &mut texts);
    tool_texts(&shipped(), &mut texts);
    for code in ErrorCode::ALL {
        let error = ToolError::new(code)
            .var("field", "target")
            .var("tool", "func_get")
            .var("kind", "set");
        texts.push((format!("{code} message"), error.message()));
        texts.push((format!("{code} hint"), code.info().hint.to_owned()));
    }
    for code in WarningCode::ALL {
        texts.push((format!("{code} message"), code.info().message.to_owned()));
        texts.push((format!("{code} hint"), code.info().hint.to_owned()));
    }
    for text in ghidorah_tools::hints::TEXTS {
        texts.push(("pipeline text".to_owned(), (*text).to_owned()));
    }
    assert!(texts.len() > 150, "{} texts", texts.len());
    let mut bad = Vec::new();
    for (place, text) in &texts {
        assert!(!text.is_empty(), "{place} is empty");
        for finding in check_agent_text(text) {
            bad.push(format!("{place}: {finding}"));
        }
    }
    assert!(bad.is_empty(), "STE findings:\n{}", bad.join("\n"));
    assert!(!check_agent_text("The value is used by the tool.").is_empty());
}
