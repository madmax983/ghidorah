//! The register checks of WP-22a, WP-22b, WP-24 and WP-25: the shipped registry holds the
//! memory, override, type, claim and batch tools in catalog order, and `session_brief` lists
//! the orphans of `ghidorah_analysis::orphans::find`.

use ghidorah_base::{Address, BinaryId};
use ghidorah_db::{Edit, SymKind};
use ghidorah_json::Value;
use ghidorah_tools::envelope::AnalysisState;
use ghidorah_tools::{Session, ToolError, handlers};

use crate::support::{DEMO_ID, call, data, registry, session, text_at};

/// The tools of WP-22a, WP-22b, WP-24 and WP-25 with their catalog numbers (design Section
/// 10.3). The shipped registry holds the tools 1 to 22 in order, so a number is one more than
/// its index.
const CATALOG: &[(usize, &str)] = &[
    (11, "fact_check"),
    (12, "type_get"),
    (14, "session_brief"),
    (16, "symbol_rename"),
    (17, "comment_set"),
    (18, "note_write"),
    (19, "func_edit"),
    (20, "type_edit"),
    (22, "batch_run"),
];

#[test]
fn shipped_registry_holds_the_memory_and_override_tools() {
    let shipped = registry();
    for (number, name) in CATALOG {
        let (index, _) = shipped
            .get(name)
            .unwrap_or_else(|| panic!("{name} is not shipped"));
        assert_eq!(index + 1, *number, "{name} is at the index {index}");
    }
    let names = shipped.names();
    assert_eq!(names.last(), Some(&"batch_run"), "{names:?}");
    for spec in [
        &handlers::session_brief::SPEC,
        &handlers::symbol_rename::SPEC,
        &handlers::comment_set::SPEC,
        &handlers::note_write::SPEC,
        &handlers::type_get::SPEC,
        &handlers::func_edit::SPEC,
        &handlers::type_edit::SPEC,
        &handlers::fact_check::SPEC,
        &handlers::batch_run::SPEC,
    ] {
        assert!(names.contains(&spec.name), "{} is not shipped", spec.name);
    }
}

/// Makes a session of the shipped registry with the analysis engine and the analyzed demo.
fn analyzed_demo() -> Session {
    let mut s = session();
    handlers::analysis_run::install(&mut s);
    let envelope = call(&mut s, "binary_load", r#"{"builtin":"demo"}"#);
    assert_eq!(text_at(&envelope, "/data/analysis/state"), "complete");
    s
}

/// Gives the `orphans` rows of a brief as `(kind, at, id)`.
fn orphan_rows(brief: &Value) -> Vec<(String, String, String)> {
    data(brief)
        .get("orphans")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .map(|o| (text_at(o, "/kind"), text_at(o, "/at"), text_at(o, "/id")))
        .collect()
}

/// Gives the `next` calls of `tool` in an envelope.
fn next_of<'a>(envelope: &'a Value, tool: &str) -> Vec<&'a Value> {
    envelope
        .get("next")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter(|c| c.get("tool").and_then(Value::as_str) == Some(tool))
        .collect()
}

#[test]
fn brief_lists_the_orphans_of_the_detector() {
    let mut s = analyzed_demo();
    let seed =
        r#"{"action":"add_ref","ref":{"from":"0x1096","to":"0x11d0","kind":"unconditional_call"}}"#;
    data(&call(&mut s, "func_edit", seed));
    data(&call(
        &mut s,
        "type_edit",
        r#"{"target":"var:0x11d0/param:0","type":"int"}"#,
    ));
    let lost = call(&mut s, "func_edit", &seed.replace("add_ref", "remove_ref"));
    data(&lost);
    let brief = call(&mut s, "session_brief", "{}");
    assert_eq!(
        orphan_rows(&brief),
        [(
            "variable".to_owned(),
            "0x11d0".to_owned(),
            "var:0x11d0/param:0".to_owned()
        )],
        "the brief and W_FACT_ORPHANED name the same fact: {lost}"
    );
    let create = next_of(&brief, "func_edit");
    assert_eq!(create.len(), 1, "{brief}");
    let call = create.first().expect("a func_edit call");
    assert_eq!(text_at(call, "/args/action"), "create", "{brief}");
    assert_eq!(text_at(call, "/args/target"), "0x11d0", "{brief}");
}

#[test]
fn brief_orphan_reference_has_no_create_call() {
    let mut s = analyzed_demo();
    let add = r#"{"action":"add_ref","ref":{"from":"0x10a1","to":"0x2004","kind":"read"}}"#;
    data(&call(&mut s, "func_edit", add));
    let flow = r#"{"action":"set_flow","at":"0x1091","flow":{"kind":"call_as_jump"}}"#;
    data(&call(&mut s, "func_edit", flow));
    let brief = call(&mut s, "session_brief", "{}");
    assert_eq!(
        orphan_rows(&brief),
        [(
            "reference".to_owned(),
            "0x10a1".to_owned(),
            "ref:0x10a1>0x2004:read".to_owned()
        )],
        "{brief}"
    );
    assert!(
        next_of(&brief, "func_edit").is_empty(),
        "func_edit create does not put a reference back: {brief}"
    );
}

#[test]
fn brief_lists_no_orphans_of_a_stale_analysis() {
    let mut s = analyzed_demo();
    let id = BinaryId::parse(DEMO_ID).expect("the ID parses");
    s.transact(id, "symbol_rename", "cli", |tx| {
        let name = tx.fact("lost_function".to_owned());
        tx.apply(Edit::SetName {
            addr: Address::ram(0x1088),
            key: None,
            kind: SymKind::Function,
            primary: true,
            name: Some(name),
            evidence: Vec::new(),
        })
        .map(drop)
        .map_err(|e| ToolError::new(e.code()))
    })
    .expect("the name commits");
    let brief = call(&mut s, "session_brief", "{}");
    assert_eq!(
        orphan_rows(&brief),
        [("name".to_owned(), "0x1088".to_owned(), "0x1088".to_owned())],
        "{brief}"
    );
    let binary = s.binary_mut(id).expect("the demo is open");
    binary.analysis = binary.analysis.map(|mut a| {
        a.state = AnalysisState::Stale;
        a
    });
    let stale = call(&mut s, "session_brief", "{}");
    assert!(orphan_rows(&stale).is_empty(), "{stale}");
    assert!(next_of(&stale, "func_edit").is_empty(), "{stale}");
}
