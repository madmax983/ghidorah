//! `symbol_rename`: one rename, item lists, variables, evidence, the write rule, dry runs,
//! `expected_rev` (AC-168) and renames after a re-analysis (AC-122).

use ghidorah_base::{Address, Fuel, Id};
use ghidorah_db::{Source, SymKind};
use ghidorah_json::Value;
use ghidorah_tools::session::FULL_BAND;

use crate::support::{
    STRIPPED, call, call_value, code, data, demo, demo_id, fixture, int_at, items, json, next0,
    program, str_of, text_at,
};

/// Gives the name of the function `id` in `func_list`.
fn listed_name(session: &mut ghidorah_tools::Session, id: &str) -> String {
    let envelope = call(session, "func_list", r#"{"limit":1000}"#);
    items(&envelope)
        .iter()
        .find(|i| str_of(i, "id") == id)
        .map(|i| str_of(i, "name"))
        .unwrap_or_default()
}

#[test]
fn rename_function_label_and_noop() {
    let (mut session, id) = fixture(STRIPPED);
    let first = call(
        &mut session,
        "symbol_rename",
        r#"{"target":"fn:0x11e0","name":"check_password"}"#,
    );
    let rev = int_at(&first, "/rev");
    let item = items(&first).first().cloned().expect("one item");
    assert_eq!(str_of(&item, "id"), "fn:0x11e0", "{first}");
    assert_eq!(str_of(&item, "old"), "FUN_000011e0");
    assert_eq!(str_of(&item, "new"), "check_password");
    assert_eq!(str_of(&item, "source"), "agent");
    assert_eq!(item.get("noop"), Some(&Value::Bool(false)));
    assert_eq!(int_at(&first, "/data/rev"), rev);
    assert_eq!(text_at(&first, "/data/tx"), text_at(&first, "/tx"));
    assert!(text_at(&first, "/tx").starts_with("tx:"), "{first}");
    assert_eq!(listed_name(&mut session, "fn:0x11e0"), "check_password");
    let p = program(&session, id);
    let symbol = p
        .primary_symbol(Address::ram(0x11e0))
        .expect("the symbol exists");
    assert_eq!(symbol.kind, SymKind::Function);
    assert_eq!(symbol.name.source, Source::Agent);

    let again = call(
        &mut session,
        "symbol_rename",
        r#"{"target":"FUN_000011e0","name":"check_password"}"#,
    );
    assert_eq!(code(&again), "", "{again}");
    assert_eq!(int_at(&again, "/rev"), rev, "a no-op keeps the rev");
    assert_eq!(again.get("noop"), Some(&Value::Bool(true)));
    assert_eq!(again.pointer("/data/tx"), Some(&Value::Null));
    assert_eq!(
        items(&again).first().and_then(|i| i.get("noop")),
        Some(&Value::Bool(true))
    );

    let label = call(
        &mut session,
        "symbol_rename",
        r#"{"target":"main+0x8","name":"after_sub"}"#,
    );
    let item = items(&label).first().cloned().expect("one item");
    assert_eq!(str_of(&item, "id"), "0x1088", "{label}");
    assert_eq!(int_at(&label, "/rev"), rev + 1);
    let p = program(&session, id);
    let symbol = p
        .primary_symbol(Address::ram(0x1088))
        .expect("the label exists");
    assert_eq!(symbol.kind, SymKind::Label);
    let found = call(&mut session, "calc", r#"{"expr":"after_sub"}"#);
    assert_eq!(text_at(&found, "/data/value"), "0x1088", "{found}");
}

#[test]
fn rename_items_in_one_transaction() {
    let (mut session, _) = fixture(STRIPPED);
    let before = int_at(&call(&mut session, "calc", r#"{"expr":"1"}"#), "/rev");
    let args = r#"{"items":[
        {"target":"fn:0x1110","name":"deregister_tm_clones"},
        {"target":"0x10","name":"nowhere"},
        {"target":"fn:0x1140","name":"register_tm_clones","evidence":["fn:0x1110"]}
    ],"evidence":["op2:Add.64,Get.gpr"],"confidence":"high"}"#;
    let envelope = call(&mut session, "symbol_rename", args);
    let d = data(&envelope);
    assert_eq!(
        d.get("ok_count").and_then(Value::as_u64),
        Some(2),
        "{envelope}"
    );
    assert_eq!(d.get("error_count").and_then(Value::as_u64), Some(1));
    let list = items(&envelope);
    assert_eq!(list.len(), 3);
    assert_eq!(list[1].get("ok"), Some(&Value::Bool(false)));
    assert_eq!(text_at(&list[1], "/error/code"), "ADDRESS_UNMAPPED");
    assert_eq!(text_at(&list[1], "/error/field_path"), "/items/1/target");
    assert_eq!(text_at(&list[0], "/data/new"), "deregister_tm_clones");
    assert_eq!(int_at(&envelope, "/rev"), before + 1, "one commit");

    let rows = call(
        &mut session,
        "history_list",
        r#"{"coalesce":false,"kinds":["name"]}"#,
    );
    let rows = items(&rows);
    assert_eq!(rows.len(), 2, "{rows:?}");
    let evidence = |i: usize| rows[i].pointer("/fields/evidence").cloned();
    assert_eq!(
        evidence(0),
        Some(json(r#"["op2:Add.64,Get.gpr","confidence:high"]"#)),
        "the call evidence and the confidence"
    );
    assert_eq!(
        evidence(1),
        Some(json(r#"["fn:0x1110","confidence:high"]"#)),
        "the item evidence replaces the call evidence"
    );
    let undo = call(&mut session, "history_undo", "{}");
    assert_eq!(code(&undo), "", "{undo}");
    let names = call(&mut session, "func_list", r#"{"limit":1000}"#);
    let named: Vec<String> = items(&names)
        .iter()
        .filter(|i| str_of(i, "name").contains("tm_clones"))
        .map(|i| str_of(i, "id"))
        .collect();
    assert!(named.is_empty(), "one undo reverts the batch: {named:?}");
}

#[test]
fn rename_variable() {
    let (mut session, id) = fixture(STRIPPED);
    let envelope = call(
        &mut session,
        "symbol_rename",
        r#"{"target":"var:0x11e0/stack:-0x14","name":"length"}"#,
    );
    let item = items(&envelope).first().cloned().expect("one item");
    assert_eq!(str_of(&item, "id"), "var:0x11e0/stack:-0x14", "{envelope}");
    assert_eq!(item.get("old"), Some(&Value::Null));
    assert_eq!(str_of(&item, "new"), "length");
    let Ok(Id::Var(var)) = Id::parse("var:0x11e0/stack:-0x14") else {
        panic!("the variable ID parses");
    };
    let p = program(&session, id);
    assert_eq!(
        p.var(&var).name.map(|f| f.value.clone()),
        Some("length".to_owned())
    );
    let missing = call(
        &mut session,
        "symbol_rename",
        r#"{"target":"var:0x11e8/stack:-0x14","name":"length"}"#,
    );
    assert_eq!(code(&missing), "NOT_FOUND", "{missing}");
}

#[test]
fn rename_imported_needs_force() {
    let mut session = demo();
    let blocked = call(
        &mut session,
        "symbol_rename",
        r#"{"target":"fn:0x1080","name":"entry_main"}"#,
    );
    assert_eq!(
        code(&blocked),
        "BLOCKED_BY_HIGHER_PRIORITY_SOURCE",
        "{blocked}"
    );
    assert_eq!(text_at(&blocked, "/error/details/source"), "imported");
    assert_eq!(text_at(&blocked, "/error/details/current"), "main");
    let (tool, args) = next0(&blocked);
    assert_eq!(tool, "symbol_rename");
    assert_eq!(args.get("force"), Some(&Value::Bool(true)), "{blocked}");
    let forced = call_value(&mut session, &tool, args);
    assert_eq!(code(&forced), "", "{forced}");
    let p = program(&session, demo_id());
    let name = p.name(Address::ram(0x1080)).expect("a name");
    assert_eq!(name.text, "entry_main");
    assert_eq!(name.source, Source::Agent);
}

#[test]
fn rename_errors_and_dry_run() {
    let (mut session, id) = fixture(STRIPPED);
    let cases = [
        (r#"{"target":"fn:0x11e0"}"#, "MISSING_ARGUMENT"),
        (r#"{"target":"fn:0x11e0","name":""}"#, "INVALID_ARGUMENT"),
        (
            r#"{"target":"fn:0x11e0","name":"a\u0007b"}"#,
            "INVALID_ARGUMENT",
        ),
        (
            r#"{"items":[{"target":"fn:0x11e0","name":"x"}],"name":"y"}"#,
            "INVALID_ARGUMENT",
        ),
        (r#"{"target":"no_such_name","name":"x"}"#, "NOT_FOUND"),
        (r#"{"target":"note:3","name":"x"}"#, "INVALID_ARGUMENT"),
    ];
    for (args, want) in cases {
        let envelope = call(&mut session, "symbol_rename", args);
        assert_eq!(code(&envelope), want, "{args}: {envelope}");
    }
    let rev = program(&session, id).rev().0;
    let dry = call(
        &mut session,
        "symbol_rename",
        r#"{"target":"fn:0x11e0","name":"check_password","dry_run":true}"#,
    );
    assert_eq!(code(&dry), "", "{dry}");
    assert_eq!(dry.get("noop"), Some(&Value::Bool(true)));
    assert_eq!(text_at(&dry, "/diff/0/op"), "SetName", "{dry}");
    assert_eq!(
        program(&session, id).rev().0,
        rev,
        "a dry run commits nothing"
    );
    assert_eq!(
        program(&session, id)
            .name(Address::ram(0x11e0))
            .map(|n| n.text),
        Some("FUN_000011e0".to_owned())
    );
}

#[test]
fn ac_168_expected_rev() {
    let (mut session, id) = fixture(STRIPPED);
    let rev = program(&session, id).rev().0;
    let args = format!(
        r#"{{"target":"fn:0x11e0","name":"check_password","expected_rev":{}}}"#,
        rev + 5
    );
    let conflict = call(&mut session, "symbol_rename", &args);
    assert_eq!(code(&conflict), "CONFLICT", "{conflict}");
    assert_eq!(int_at(&conflict, "/error/details/current_rev"), rev);
    let (tool, next) = next0(&conflict);
    assert_eq!(tool, "symbol_rename");
    assert_eq!(next.get("expected_rev").and_then(Value::as_u64), Some(rev));
    let done = call_value(&mut session, &tool, next);
    assert_eq!(code(&done), "", "{done}");
    assert_eq!(int_at(&done, "/rev"), rev + 1);
    let stale = call(
        &mut session,
        "comment_set",
        &format!(r#"{{"target":"0x11e0","kind":"eol","text":"x","expected_rev":{rev}}}"#),
    );
    assert_eq!(code(&stale), "CONFLICT", "{stale}");
    let note = call(
        &mut session,
        "note_write",
        &format!(r#"{{"kind":"todo","text":"x","expected_rev":{}}}"#, rev + 1),
    );
    assert_eq!(code(&note), "", "{note}");
}

#[test]
fn ac_122_rename_survives_reanalysis() {
    let (mut session, id) = fixture(STRIPPED);
    let renamed = call(
        &mut session,
        "symbol_rename",
        r#"{"items":[{"target":"fn:0x11e0","name":"check_password"},{"target":"fn:0x1080","name":"real_main"}]}"#,
    );
    assert_eq!(int_at(&renamed, "/data/ok_count"), 2, "{renamed}");
    let mut fuel = Fuel::new(500_000_000);
    let report = session
        .reanalyze(id, FULL_BAND, &mut fuel)
        .expect("the re-analysis runs")
        .expect("the session has an engine");
    assert_eq!(report.state.as_str(), "complete");
    assert!(report.steps_used > 0, "the re-analysis does work");
    assert_eq!(listed_name(&mut session, "fn:0x11e0"), "check_password");
    assert_eq!(listed_name(&mut session, "fn:0x1080"), "real_main");
    let got = call(&mut session, "func_get", r#"{"target":"check_password"}"#);
    assert_eq!(text_at(&got, "/data/id"), "fn:0x11e0", "{got}");
    let p = program(&session, id);
    for (entry, name) in [(0x11e0, "check_password"), (0x1080, "real_main")] {
        let found = p.name(Address::ram(entry)).expect("a name");
        assert_eq!((found.text.as_str(), found.source), (name, Source::Agent));
        assert!(p.func(ghidorah_base::FuncId(Address::ram(entry))).is_some());
    }
}
