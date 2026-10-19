//! AC-241: the `next` batch of a proposal call applies every proposal through `symbol_rename`
//! with its evidence in one transaction, and one `history_undo` reverts all the renames.

use ghidorah_base::Address;
use ghidorah_json::Value;

use crate::support::{
    FULL, STRIPPED, call, call_value, code, data, default_named, int_at, list_at, next_calls, open,
    program, similar_args, text_at,
};

/// Gives the name of the function `id` in the open binary `bin`.
fn name_of(s: &ghidorah_tools::Session, bin: ghidorah_base::BinaryId, id: &str) -> (String, bool) {
    let addr = id
        .strip_prefix("fn:0x")
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .expect("a fn: ID");
    let name = program(s, bin).name(Address::ram(addr)).expect("a name");
    let default = name.is_default();
    (name.text, default)
}

#[test]
fn ac_241_batch_applies_proposals() {
    let (mut s, ids) = open(&[STRIPPED, FULL]);
    let bin = ids[0];
    let targets: Vec<Value> = default_named(&s, bin)
        .into_iter()
        .take(20)
        .map(Value::from)
        .collect();
    let mut args = similar_args(bin, r#"{"scope":"open","propose_names":true}"#);
    if let Value::Object(object) = &mut args {
        object.push("targets", Value::Array(targets));
    }
    let envelope = call_value(&mut s, "func_similar", args);
    let d = data(&envelope);
    let renames = list_at(d, "/renames");
    assert!(renames.len() >= 3, "{envelope}");
    let proposals: Vec<Value> = list_at(d, "/items")
        .iter()
        .filter_map(|i| i.get("proposal").cloned())
        .collect();
    assert_eq!(proposals.len(), renames.len(), "one rename per proposal");
    for (p, r) in proposals.iter().zip(&renames) {
        assert_eq!(text_at(p, "/name"), text_at(r, "/name"));
        assert_eq!(p.get("evidence"), r.get("evidence"));
        assert!(int_at(p, "/score") >= 800, "{p}");
        assert_eq!(text_at(p, "/from/binary_id"), ids[1].to_string());
        assert!(!list_at(r, "/evidence").is_empty(), "{r}");
    }
    let rev = int_at(&envelope, "/rev");

    let calls = next_calls(&envelope);
    assert_eq!(
        calls.first().map(|c| c.0.as_str()),
        Some("batch_run"),
        "{envelope}"
    );
    let batch = call_value(&mut s, "batch_run", calls[0].1.clone());
    assert_eq!(code(&batch), "", "{batch}");
    assert_eq!(int_at(&batch, "/rev"), rev + 1, "one transaction: {batch}");
    for r in &renames {
        let target = text_at(r, "/target");
        let (name, default) = name_of(&s, bin, &target);
        assert_eq!(name, text_at(r, "/name"), "{target}");
        assert!(!default);
    }
    let rows = call(
        &mut s,
        "history_list",
        &format!(r#"{{"binary_id":"{bin}","coalesce":false,"kinds":["name"]}}"#),
    );
    let rows = list_at(data(&rows), "/items");
    assert_eq!(rows.len(), renames.len(), "{rows:?}");
    for r in &renames {
        let want = r.get("evidence").cloned();
        assert!(
            rows.iter()
                .any(|row| row.pointer("/fields/evidence").cloned() == want),
            "the journal keeps the evidence {want:?}: {rows:?}"
        );
    }

    let undo = call(
        &mut s,
        "history_undo",
        &format!(r#"{{"binary_id":"{bin}"}}"#),
    );
    assert_eq!(code(&undo), "", "{undo}");
    for r in &renames {
        let (_, default) = name_of(&s, bin, &text_at(r, "/target"));
        assert!(default, "one undo reverts every rename of the batch");
    }
    let again = call_value(&mut s, "batch_run", calls[0].1.clone());
    assert_eq!(code(&again), "", "{again}");
    let mut step = calls[0]
        .1
        .pointer("/steps/0/args")
        .cloned()
        .unwrap_or_default();
    if let Value::Object(object) = &mut step {
        object.push("binary_id", Value::from(bin.to_string()));
    }
    let after = call_value(&mut s, "func_similar", step);
    assert!(
        list_at(data(&after), "/renames").is_empty(),
        "an agent name gets no proposal: {after}"
    );
}
