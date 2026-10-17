//! The actions of `func_edit` on the demo binary: facts, errors, dry runs and no-ops.
//!
//! The demo binary is `crackme.gcc-O2`. `hidden_gate` at `0x11d0` is code that no function
//! owns. `register_tm_clones` at `0x1140` has an unresolved indirect jump at `0x1170`.

use ghidorah_base::{Address, FuncId, JumpTableId};
use ghidorah_db::{FlowOverride, Source};
use ghidorah_json::Value;

use crate::support::{call, caveats, code, data, demo, program, text_at, warnings};

#[test]
fn create_makes_an_agent_function() {
    let mut s = demo();
    let rev = program(&s).rev().0;
    let envelope = call(
        &mut s,
        "func_edit",
        r#"{"action":"create","target":"0x11d0"}"#,
    );
    let out = data(&envelope);
    assert_eq!(text_at(out, "/action"), "create");
    assert_eq!(text_at(out, "/target"), "fn:0x11d0");
    assert_eq!(text_at(out, "/analysis/state"), "complete", "{envelope}");
    assert!(
        out.pointer("/analysis/steps_used")
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0),
        "the re-analysis runs"
    );
    assert!(out.get("rev").and_then(Value::as_u64) > Some(rev));
    assert_eq!(envelope.get("noop"), Some(&Value::Bool(false)));
    let p = program(&s);
    let id = FuncId(Address::ram(0x11d0));
    let base = p.base().funcs().get(id).expect("the agent record");
    assert_eq!(base.source, Source::Agent);
    let view = p.func(id).expect("the function");
    assert!(
        view.func.body.contains(0x11d7),
        "the analysis decodes the body"
    );
    let listed = call(&mut s, "func_get", r#"{"target":"fn:0x11d0"}"#);
    assert_eq!(text_at(data(&listed), "/start_reason"), "agent");
}

#[test]
fn create_name_over_an_imported_symbol_needs_force() {
    let mut s = demo();
    let args = r#"{"action":"create","target":"0x11d0","name":"gate_check"}"#;
    let blocked = call(&mut s, "func_edit", args);
    assert_eq!(
        code(&blocked),
        "BLOCKED_BY_HIGHER_PRIORITY_SOURCE",
        "{blocked}"
    );
    assert_eq!(text_at(&blocked, "/error/details/source"), "imported");
    assert_eq!(
        blocked.pointer("/next/0/args/force"),
        Some(&Value::Bool(true)),
        "next[0] repeats the call with force: {blocked}"
    );
    assert!(
        program(&s)
            .base()
            .funcs()
            .get(FuncId(Address::ram(0x11d0)))
            .is_none()
    );
    let forced = r#"{"action":"create","target":"0x11d0","name":"gate_check","force":true}"#;
    let envelope = call(&mut s, "func_edit", forced);
    data(&envelope);
    let name = program(&s).name(Address::ram(0x11d0)).expect("a name");
    assert_eq!(name.text, "gate_check");
    assert_eq!(name.source, Source::Agent);
}

#[test]
fn create_needs_an_instruction_start_in_code() {
    let mut s = demo();
    let inside = call(
        &mut s,
        "func_edit",
        r#"{"action":"create","target":"0x11d1"}"#,
    );
    assert_eq!(code(&inside), "INVALID_ARGUMENT", "{inside}");
    let data_addr = call(
        &mut s,
        "func_edit",
        r#"{"action":"create","target":"0x2004"}"#,
    );
    assert_eq!(code(&data_addr), "INVALID_ARGUMENT", "{data_addr}");
    let unmapped = call(
        &mut s,
        "func_edit",
        r#"{"action":"create","target":"0x900000"}"#,
    );
    assert_eq!(code(&unmapped), "ADDRESS_UNMAPPED", "{unmapped}");
}

#[test]
fn delete_removes_only_agent_functions() {
    let mut s = demo();
    let found = call(
        &mut s,
        "func_edit",
        r#"{"action":"delete","target":"fn:0x11e0"}"#,
    );
    assert_eq!(code(&found), "NOT_FOUND", "{found}");
    assert!(program(&s).func(FuncId(Address::ram(0x11e0))).is_some());
    data(&call(
        &mut s,
        "func_edit",
        r#"{"action":"create","target":"0x11d0"}"#,
    ));
    let envelope = call(
        &mut s,
        "func_edit",
        r#"{"action":"delete","target":"fn:0x11d0"}"#,
    );
    assert_eq!(text_at(data(&envelope), "/target"), "fn:0x11d0");
    let p = program(&s);
    let id = FuncId(Address::ram(0x11d0));
    assert!(p.base().funcs().get(id).is_none());
    assert!(p.func(id).is_none(), "the re-analysis drops the function");
}

#[test]
fn set_noreturn_needs_a_function() {
    let mut s = demo();
    let none = call(
        &mut s,
        "func_edit",
        r#"{"action":"set_noreturn","target":"fn:0x11d0","noreturn":true}"#,
    );
    assert_eq!(code(&none), "NOT_FOUND", "{none}");
    let missing = call(
        &mut s,
        "func_edit",
        r#"{"action":"set_noreturn","target":"main"}"#,
    );
    assert_eq!(code(&missing), "MISSING_ARGUMENT", "{missing}");
    let args = r#"{"action":"set_noreturn","target":"fn:0x11e0","noreturn":false}"#;
    data(&call(&mut s, "func_edit", args));
    let again = call(&mut s, "func_edit", args);
    assert_eq!(again.get("noop"), Some(&Value::Bool(true)), "{again}");
    let fact = program(&s)
        .base()
        .funcs()
        .get(FuncId(Address::ram(0x11e0)))
        .and_then(|f| f.flags.noreturn.clone())
        .expect("the agent flag");
    assert!(!fact.value);
}

#[test]
fn set_jumptable_resolves_the_caveat() {
    let mut s = demo();
    let before = caveats(&mut s, "fn:0x1140");
    assert!(
        before
            .iter()
            .any(|c| text_at(c, "/code") == "W_JUMPTABLE_UNRESOLVED"),
        "{before:?}"
    );
    let args = r#"{"action":"set_jumptable","at":"0x1170","targets":["0x1178"]}"#;
    let envelope = call(&mut s, "func_edit", args);
    assert_eq!(text_at(data(&envelope), "/target"), "0x1170");
    let after = caveats(&mut s, "fn:0x1140");
    assert!(
        !after
            .iter()
            .any(|c| text_at(c, "/code") == "W_JUMPTABLE_UNRESOLVED"),
        "{after:?}"
    );
    let table = program(&s)
        .base()
        .jumptables()
        .get(JumpTableId(Address::ram(0x1170)))
        .expect("the agent table");
    assert_eq!(table.value.targets, vec![Address::ram(0x1178)]);
}

#[test]
fn site_actions_check_the_instruction() {
    let mut s = demo();
    let call_site = call(
        &mut s,
        "func_edit",
        r#"{"action":"set_jumptable","at":"0x1091","targets":["0x1096"]}"#,
    );
    assert_eq!(code(&call_site), "INVALID_ARGUMENT", "{call_site}");
    let direct = call(
        &mut s,
        "func_edit",
        r#"{"action":"set_call_targets","at":"0x1091","targets":["fn:0x11c0"]}"#,
    );
    assert_eq!(code(&direct), "INVALID_ARGUMENT", "{direct}");
    let bad_target = call(
        &mut s,
        "func_edit",
        r#"{"action":"set_jumptable","at":"0x1170","targets":["0x1171"]}"#,
    );
    assert_eq!(code(&bad_target), "INVALID_ARGUMENT", "{bad_target}");
    let no_to = call(
        &mut s,
        "func_edit",
        r#"{"action":"set_flow","at":"0x1098","flow":{"kind":"fallthrough"}}"#,
    );
    assert_eq!(code(&no_to), "MISSING_ARGUMENT", "{no_to}");
    let wrong = call(
        &mut s,
        "func_edit",
        r#"{"action":"set_flow","at":"0x1098","flow":{"kind":"call_as_jump"}}"#,
    );
    assert_eq!(code(&wrong), "INVALID_ARGUMENT", "{wrong}");
}

#[test]
fn set_flow_clear_removes_the_override() {
    let mut s = demo();
    let at = Address::ram(0x10c7);
    let set = r#"{"action":"set_flow","at":"0x10c7","flow":{"kind":"call_as_jump"}}"#;
    data(&call(&mut s, "func_edit", set));
    assert_eq!(
        program(&s)
            .base()
            .overrides()
            .get(at)
            .map(|f| f.value.clone()),
        Some(FlowOverride::CallAsJump)
    );
    let clear = r#"{"action":"set_flow","at":"0x10c7","flow":{"kind":"clear"}}"#;
    data(&call(&mut s, "func_edit", clear));
    assert!(program(&s).base().overrides().get(at).is_none());
    let fall = r#"{"action":"set_flow","at":"0x1098","flow":{"kind":"fallthrough","to":"0x109a"}}"#;
    data(&call(&mut s, "func_edit", fall));
    assert_eq!(
        program(&s)
            .base()
            .overrides()
            .get(Address::ram(0x1098))
            .map(|f| f.value.clone()),
        Some(FlowOverride::Fallthrough(Address::ram(0x109a)))
    );
}

#[test]
fn refs_need_code_and_agent_facts() {
    let mut s = demo();
    let inside = call(
        &mut s,
        "func_edit",
        r#"{"action":"add_ref","ref":{"from":"0x1092","to":"0x2004","kind":"read"}}"#,
    );
    assert_eq!(code(&inside), "INVALID_ARGUMENT", "{inside}");
    let analysis = call(
        &mut s,
        "func_edit",
        r#"{"action":"remove_ref","ref":{"from":"0x1091","to":"0x11e0","kind":"unconditional_call"}}"#,
    );
    assert_eq!(code(&analysis), "NOT_FOUND", "{analysis}");
    let add = r#"{"action":"add_ref","ref":{"from":"0x10f8","to":"0x2004","kind":"read"}}"#;
    let envelope = call(&mut s, "func_edit", add);
    assert_eq!(
        text_at(data(&envelope), "/target"),
        "ref:0x10f8>0x2004:read"
    );
    let refs = program(&s).refs_from(Address::ram(0x10f8));
    assert!(
        refs.iter()
            .any(|r| r.source == Source::Agent && r.value.key.to == Address::ram(0x2004)),
        "the agent reference"
    );
}

#[test]
fn dry_run_changes_nothing() {
    let mut s = demo();
    let rev = program(&s).rev();
    let args = r#"{"action":"create","target":"0x11d0","dry_run":true}"#;
    let envelope = call(&mut s, "func_edit", args);
    data(&envelope);
    assert_eq!(envelope.get("noop"), Some(&Value::Bool(true)), "{envelope}");
    let diff = envelope
        .get("diff")
        .and_then(Value::as_array)
        .expect("a dry run has a diff");
    assert_eq!(
        diff.first().map(|d| text_at(d, "/op")),
        Some("CreateFunction".to_owned())
    );
    assert_eq!(program(&s).rev(), rev);
    assert!(program(&s).func(FuncId(Address::ram(0x11d0))).is_none());
    assert!(warnings(&envelope, "W_FACT_ORPHANED").is_empty());
}
