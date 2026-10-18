//! Verdicts after an indirect target override and after its undo (AC-204a, AC-204b).

use ghidorah_json::Value;
use ghidorah_tools::Session;

use crate::support::{call, data, open, text_at, texts, verdict_of};

/// The indirect call of `fire` in `func_ptrs.gcc-O0`: `call rdx` through the callback slot.
const SITE: &str = "0x1302";

/// Gives the verdicts of `calls(fire, log_event)` and `calls(fire, op_add)`.
fn both(s: &mut Session) -> (Value, Value) {
    (
        verdict_of(s, "calls", &["fire", "log_event"]),
        verdict_of(s, "calls", &["fire", "op_add"]),
    )
}

/// Opens the fixture and sets the targets of the site to `log_event`.
fn resolved() -> Session {
    let (mut s, _) = open("fixtures/bin/func_ptrs.gcc-O0");
    let (hit, other) = both(&mut s);
    for v in [&hit, &other] {
        assert_eq!(text_at(v, "/verdict"), "unknown", "{v}");
        assert_eq!(texts(v, "/basis/gaps"), [SITE], "{v}");
    }
    let edit = call(
        &mut s,
        "func_edit",
        &format!(r#"{{"action":"set_call_targets","at":"{SITE}","targets":["log_event"]}}"#),
    );
    assert_eq!(
        text_at(data(&edit), "/analysis/state"),
        "complete",
        "{edit}"
    );
    s
}

#[test]
fn ac_204a_call_targets_verdicts() {
    let mut s = resolved();
    let (hit, other) = both(&mut s);
    assert_eq!(text_at(&hit, "/verdict"), "supported", "{hit}");
    assert!(
        texts(&hit, "/evidence").contains(&SITE.to_owned()),
        "the override site is evidence: {hit}"
    );
    assert_eq!(text_at(&other, "/verdict"), "refuted", "{other}");
    assert_eq!(
        other.pointer("/basis/complete"),
        Some(&Value::Bool(true)),
        "{other}"
    );
    assert_eq!(
        texts(&other, "/basis/gaps"),
        Vec::<String>::new(),
        "{other}"
    );
    let uses = verdict_of(&mut s, "uses_import", &["fire", "imp:printf"]);
    assert_eq!(text_at(&uses, "/verdict"), "refuted", "{uses}");
    let path = verdict_of(&mut s, "reaches", &["fire", "imp:printf", "2"]);
    assert_eq!(text_at(&path, "/verdict"), "supported", "{path}");
}

#[test]
fn ac_204b_undo_restores_unknown() {
    let mut s = resolved();
    let undo = call(&mut s, "history_undo", "{}");
    data(&undo);
    let (hit, other) = both(&mut s);
    for v in [&hit, &other] {
        assert_eq!(text_at(v, "/verdict"), "unknown", "{v}");
        assert_eq!(texts(v, "/basis/gaps"), [SITE], "{v}");
    }
}
