//! The re-analysis after an override (design Section 3.9): persistence, conflicts, fuel stops,
//! stale reads, start bands, call targets and orphans.

use ghidorah_analysis::orphans::{OrphanKind, find};
use ghidorah_base::{Address, BinaryId, Fuel, FuncId, Id, JumpTableId};
use ghidorah_db::{FlowOverride, RefKey, RefType, Source};
use ghidorah_json::Value;

use crate::support::{
    DEMO_ID, call, call_value, caveats, config, config_in, data, demo, items, load_demo, program,
    session_with, text_at, tmp, warnings,
};

/// The demo binary ID.
fn demo_id() -> BinaryId {
    BinaryId::parse(DEMO_ID).expect("the ID parses")
}

/// Runs the `func_edit` example `args` on the demo in the project `dir`, after the example
/// that makes its fact. The edit must start a re-analysis that completes.
fn edit_in_project(dir: &std::path::Path, args: &str) {
    let mut s = session_with(config_in(dir));
    load_demo(&mut s);
    if let Some(setup) = ghidorah_tools::handlers::func_edit::setup_of(args) {
        data(&call(&mut s, "func_edit", setup));
    }
    let envelope = call(&mut s, "func_edit", args);
    let out = data(&envelope);
    assert_eq!(text_at(out, "/analysis/state"), "complete", "{envelope}");
    assert!(
        out.pointer("/analysis/steps_used")
            .and_then(Value::as_u64)
            .is_some_and(|n| n > 0),
        "{args}: the edit starts a re-analysis: {envelope}"
    );
    assert!(envelope.get("tx").and_then(Value::as_str).is_some());
    let rows = items(&call(&mut s, "history_list", r#"{"since_rev":1}"#));
    assert!(!rows.is_empty(), "{args}: a history row");
}

/// Opens the demo again from the project `dir` with `binary_load { binary_id }`.
fn reopen(dir: &std::path::Path) -> ghidorah_tools::Session {
    let mut s = session_with(config_in(dir));
    let reopen = call(
        &mut s,
        "binary_load",
        &format!(r#"{{"binary_id":"{DEMO_ID}"}}"#),
    );
    data(&reopen);
    assert_eq!(
        text_at(&reopen, "/analysis/state"),
        "complete",
        "the analysis of the project is current: {reopen}"
    );
    s
}

/// Tells if the program has the agent reference of the `add_ref` example.
fn agent_ref(p: &ghidorah_db::Program) -> bool {
    p.refs_from(Address::ram(0x10f8)).iter().any(|r| {
        r.source == Source::Agent
            && r.value.key.to == Address::ram(0x11d0)
            && r.value.key.kind == RefType::Data
    })
}

/// Checks the fact of the `func_edit` action `action` after a reopen: it holds with the source
/// `agent`, or for `delete` and `remove_ref` it stays absent.
fn check_persisted(action: &str, p: &ghidorah_db::Program) {
    let b = p.base();
    let at = |a: u64| Address::ram(a);
    match action {
        "create" => {
            let f = b
                .funcs()
                .get(FuncId(at(0x11d0)))
                .expect("the agent function");
            assert_eq!(f.source, Source::Agent);
            assert!(p.func(FuncId(at(0x11d0))).is_some());
        }
        "delete" => {
            assert!(
                b.funcs().get(FuncId(at(0x11d0))).is_none(),
                "the record stays gone"
            );
            assert!(
                p.func(FuncId(at(0x11d0))).is_none(),
                "the function stays gone"
            );
        }
        "set_noreturn" => {
            let fact = b
                .funcs()
                .get(FuncId(at(0x11e0)))
                .and_then(|f| f.flags.noreturn.clone())
                .expect("the override");
            assert_eq!((fact.value, fact.source), (false, Source::Agent));
        }
        "set_jumptable" => {
            let table = b
                .jumptables()
                .get(JumpTableId(at(0x1170)))
                .expect("the agent table");
            assert_eq!(table.source, Source::Agent);
            assert_eq!(table.value.targets, vec![at(0x1178)]);
        }
        "set_flow" | "set_call_targets" => {
            let (site, want) = if action == "set_flow" {
                (0x10c7, FlowOverride::CallAsJump)
            } else {
                (0x1014, FlowOverride::IndirectTargets(vec![at(0x11c0)]))
            };
            let fact = b.overrides().get(at(site)).expect("the flow override");
            assert_eq!((&fact.value, fact.source), (&want, Source::Agent));
        }
        "add_ref" => assert!(agent_ref(p), "the agent reference"),
        "remove_ref" => assert!(!agent_ref(p), "the reference stays gone"),
        other => panic!("no check for the action {other}"),
    }
}

#[test]
fn ac_163a_override_persists() {
    let actions = ghidorah_tools::handlers::func_edit::SPEC.actions;
    assert_eq!(actions.len(), 8);
    for action in actions {
        let dir = tmp(&format!("persist_{}", action.value));
        edit_in_project(&dir, action.example);
        let s = reopen(&dir);
        check_persisted(action.value, program(&s));
    }
}

#[test]
fn ac_163b_override_conflict() {
    let mut s = demo();
    let args = r#"{"action":"set_noreturn","target":"fn:0x11e0","noreturn":true}"#;
    let envelope = call(&mut s, "func_edit", args);
    data(&envelope);
    let warned = warnings(&envelope, "W_AGENT_OVERRIDE_CONFLICT");
    assert_eq!(warned.len(), 1, "{envelope}");
    assert_eq!(
        warned
            .first()
            .and_then(|w| w.pointer("/remedy/args/noreturn")),
        Some(&Value::Bool(false)),
        "the remedy sets the analysis value: {envelope}"
    );
    let found = caveats(&mut s, "fn:0x11e0");
    let conflict = found
        .iter()
        .find(|c| text_at(c, "/code") == "W_AGENT_OVERRIDE_CONFLICT")
        .expect("the conflict caveat");
    assert_eq!(
        conflict.pointer("/remedy/args/noreturn"),
        Some(&Value::Bool(false)),
        "the caveat remedy sets the analysis value: {conflict}"
    );
    let get = call(&mut s, "func_get", r#"{"target":"fn:0x11e0"}"#);
    let flags = data(&get)
        .get("flags")
        .and_then(Value::as_array)
        .expect("flags");
    assert!(
        flags.contains(&Value::from("noreturn")),
        "the agent flag stays: {get}"
    );
}

/// Runs `analysis_run` until the analysis is complete.
fn complete(s: &mut ghidorah_tools::Session) {
    for _ in 0..1_000 {
        let envelope = call(s, "analysis_run", r#"{"max_steps":50}"#);
        if text_at(data(&envelope), "/state") == "complete" {
            return;
        }
    }
    panic!("the analysis does not complete");
}

#[test]
fn ac_203_fuel_stopped_edit_resumes() {
    let mut stopped = demo();
    let short = r#"{"action":"create","target":"0x11d0","max_steps":20}"#;
    let envelope = call(&mut stopped, "func_edit", short);
    let out = data(&envelope);
    assert_eq!(text_at(out, "/analysis/state"), "stale", "{envelope}");
    assert_eq!(
        warnings(&envelope, "W_ANALYSIS_STALE").len(),
        1,
        "{envelope}"
    );
    complete(&mut stopped);
    let mut full = demo();
    let long = r#"{"action":"create","target":"0x11d0","max_steps":100000000}"#;
    let envelope = call(&mut full, "func_edit", long);
    assert_eq!(text_at(data(&envelope), "/analysis/state"), "complete");
    assert_eq!(
        program(&stopped).state_hash().expect("a hash"),
        program(&full).state_hash().expect("a hash"),
        "the resumed run gives the state of one unlimited run"
    );
}

#[test]
fn ac_211_stale_reads() {
    let mut s = demo();
    let committed = program(&s).analysis().clone();
    let envelope = call(
        &mut s,
        "func_edit",
        r#"{"action":"create","target":"0x11d0","max_steps":20}"#,
    );
    assert_eq!(text_at(data(&envelope), "/analysis/state"), "stale");
    let read = call(&mut s, "func_list", "{}");
    data(&read);
    assert_eq!(read.get("partial"), Some(&Value::Bool(true)), "{read}");
    assert_eq!(text_at(&read, "/analysis/state"), "stale", "{read}");
    assert_eq!(
        read.pointer("/next/0/tool").and_then(Value::as_str),
        Some("analysis_run"),
        "{read}"
    );
    assert!(
        *program(&s).analysis() == committed,
        "reads use the committed analysis set"
    );
    let run = call(&mut s, "analysis_run", "{}");
    assert_eq!(text_at(data(&run), "/state"), "complete", "{run}");
    let after = call(&mut s, "func_list", "{}");
    assert_eq!(after.get("partial"), Some(&Value::Bool(false)), "{after}");
    assert!(
        *program(&s).analysis() != committed,
        "the shadow set is in place"
    );
}

#[test]
fn ac_210_band_800_rerun() {
    let sig = r#"{"target":"fn:0x11e0","signature":"int check_password(const char *input)"}"#;
    let mut s = demo();
    let id = demo_id();
    let before = s.analyzer_rows(id);
    assert!(!before.is_empty(), "the engine has rows");
    let envelope = call(&mut s, "type_edit", sig);
    assert_eq!(
        text_at(data(&envelope), "/analysis/state"),
        "complete",
        "{envelope}"
    );
    let after = s.analyzer_rows(id);
    let mut reran = 0;
    for (b, a) in before.iter().zip(&after) {
        assert_eq!(b.name, a.name);
        if b.priority < 800 {
            assert_eq!(a.runs, b.runs, "{} below band 800 does not run", b.name);
        } else if a.runs > b.runs {
            reran += 1;
        }
    }
    assert!(reran > 0, "the bands 800 and above run again");
    let mut full = demo();
    data(&call(&mut full, "type_edit", sig));
    full.reanalyze(id, 100, &mut Fuel::unlimited())
        .expect("a re-analysis from band 100");
    assert!(
        program(&s).analysis() == program(&full).analysis(),
        "the band 800 result equals a re-analysis from band 100"
    );
}

/// Gives the computed calls to `0x11c0` in an `xref_list` envelope.
fn computed_calls(envelope: &Value) -> usize {
    items(envelope)
        .iter()
        .filter(|i| text_at(i, "/kind") == "computed_call" && text_at(i, "/from") == "0x1014")
        .count()
}

#[test]
fn ac_205_call_targets_xref() {
    let mut s = demo();
    let xrefs = r#"{"targets":["fn:0x11c0"]}"#;
    let before = call(&mut s, "xref_list", xrefs);
    assert_eq!(computed_calls(&before), 0, "{before}");
    // The analysis resolves the `call rax` of `_init` through the slot of `__gmon_start__`.
    assert_eq!(
        data(&before).pointer("/basis/complete"),
        Some(&Value::Bool(true)),
        "no indirect site is open: {before}"
    );
    let set = r#"{"action":"set_call_targets","at":"0x1014","targets":["fn:0x11c0"]}"#;
    data(&call(&mut s, "func_edit", set));
    let after = call(&mut s, "xref_list", xrefs);
    assert_eq!(computed_calls(&after), 1, "the agent targets win: {after}");
    assert_eq!(
        data(&after).pointer("/basis/complete"),
        Some(&Value::Bool(true)),
        "{after}"
    );
    let undo = call(&mut s, "history_undo", "{}");
    data(&undo);
    let undone = call(&mut s, "xref_list", xrefs);
    assert_eq!(
        computed_calls(&undone),
        0,
        "history_undo removes the edge: {undone}"
    );
}

#[test]
fn ac_126_orphaned_facts() {
    let mut s = demo();
    let seed =
        r#"{"action":"add_ref","ref":{"from":"0x1096","to":"0x11d0","kind":"unconditional_call"}}"#;
    data(&call(&mut s, "func_edit", seed));
    let id = FuncId(Address::ram(0x11d0));
    assert!(
        program(&s).analysis().func(id).is_some(),
        "the reference seeds a function"
    );
    let var = r#"{"target":"var:0x11d0/param:0","type":"int"}"#;
    data(&call(&mut s, "type_edit", var));
    let unseed = seed.replace("add_ref", "remove_ref");
    let envelope = call(&mut s, "func_edit", &unseed);
    data(&envelope);
    assert!(
        program(&s).analysis().func(id).is_none(),
        "the function is gone"
    );
    let orphaned = warnings(&envelope, "W_FACT_ORPHANED");
    assert_eq!(orphaned.len(), 1, "{envelope}");
    let warning = orphaned.first().expect("the warning");
    assert_eq!(text_at(warning, "/at"), "var:0x11d0/param:0");
    assert_eq!(
        text_at(warning, "/remedy/args/action"),
        "create",
        "{warning}"
    );
    assert_eq!(
        text_at(warning, "/remedy/args/target"),
        "0x11d0",
        "{warning}"
    );
    let Ok(Id::Var(v)) = Id::parse("var:0x11d0/param:0") else {
        panic!("a variable ID");
    };
    assert!(program(&s).var(&v).ty.is_some(), "the fact stays");
    let found = find(program(&s));
    assert_eq!(
        found.iter().map(|o| o.kind).collect::<Vec<_>>(),
        [OrphanKind::Var]
    );
}

#[test]
fn regress_orphan_agent_ref_keeps_fact() {
    let mut s = demo();
    let add = r#"{"action":"add_ref","ref":{"from":"0x10a1","to":"0x2004","kind":"read"}}"#;
    data(&call(&mut s, "func_edit", add));
    // The call to check_password becomes a jump, so no flow reaches the code after it.
    let flow = r#"{"action":"set_flow","at":"0x1091","flow":{"kind":"call_as_jump"}}"#;
    let envelope = call(&mut s, "func_edit", flow);
    data(&envelope);
    assert!(
        program(&s).code_unit(0x10a1).is_none(),
        "the source is not code"
    );
    let key = RefKey {
        from: Address::ram(0x10a1),
        op_index: 0,
        to: Address::ram(0x2004),
        kind: RefType::Read,
    };
    assert!(
        program(&s).base().refs().get(&key).is_some(),
        "the agent fact stays"
    );
    let orphaned = warnings(&envelope, "W_FACT_ORPHANED");
    assert_eq!(orphaned.len(), 1, "{envelope}");
    assert_eq!(
        orphaned.first().map(|w| text_at(w, "/at")),
        Some("ref:0x10a1>0x2004:read".to_owned())
    );
    assert!(program(&s).check_invariants().is_empty());
}

#[test]
fn an_edit_without_an_engine_makes_the_analysis_stale() {
    let mut s = ghidorah_tools::Session::with_registry(
        crate::support::registry(),
        config(),
        Box::new(ghidorah_base::FixedClock::new(0)),
    );
    let load = call(
        &mut s,
        "binary_load",
        r#"{"builtin":"demo","analysis":"none"}"#,
    );
    data(&load);
    let args = Value::object([
        ("action", Value::from("create")),
        ("target", Value::from("0x11d0")),
    ]);
    let envelope = call_value(&mut s, "func_edit", args);
    let out = data(&envelope);
    assert_eq!(
        out.pointer("/analysis/steps_used").and_then(Value::as_u64),
        Some(0),
        "{envelope}"
    );
}
