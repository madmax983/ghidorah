use ghidorah_json::{Limits, Value, parse};

use super::{hex_tokens, lint, looks_like_address, schema_ok};
use crate::inputs::Question;
use crate::runner::Outcome;
use crate::scenario;

fn json(text: &str) -> Value {
    parse(text, &Limits::DEFAULT).expect("the test JSON parses")
}

fn question() -> Question {
    Question {
        id: "q-x".to_owned(),
        category: "locate".to_owned(),
        fixture: "f".to_owned(),
        binaries: vec!["fixtures/bin/f".to_owned()],
        text: "Where does the function check_input start?".to_owned(),
        check: "equals".to_owned(),
        value: json(r#""0x11e0""#),
    }
}

fn outcome(responses: &[&str]) -> Outcome {
    Outcome {
        id: "x".to_owned(),
        question: "q-x".to_owned(),
        category: "locate".to_owned(),
        pass: true,
        answer_ok: true,
        budget_ok: true,
        answer: None,
        error: None,
        calls: 0,
        chars: 0,
        peak: 0,
        est_tokens: 0,
        responses: responses.iter().map(|r| json(r)).collect(),
        sent: Vec::new(),
    }
}

fn reasons(file: &str, responses: &[&str]) -> Vec<String> {
    let s = scenario::parse("x.json", file).expect("the scenario parses");
    lint(
        &s,
        &question(),
        &outcome(responses),
        "Use func_get {target, include:[\"decomp\"]}.",
    )
    .findings
    .into_iter()
    .map(|f| format!("{} {}", f.path, f.reason))
    .collect()
}

const GOOD: &str = r#"{"id":"x","question":"q-x","turns":[
  {"call":{"tool":"binary_load","args":{"path":"fixtures/bin/f"}}},
  {"call":{"tool":"func_get","args":{"target":"check_input","include":["decomp"]}}},
  {"call":{"tool":"mem_read","args":{"target":{"$turn":1,"ptr":"/data/entry"},"as":"insn","count":2}}}],
  "answer":{"turn":2,"ptr":"/data/addr"},
  "provenance":{"/turns/0/call/args/path":"question:binaries/0","/turns/1/call/args/target":"question",
    "/turns/1/call/args/include/0":"instructions","/turns/2/call/args/as":"schema:mem_read.as",
    "/turns/2/call/args/count":"schema:mem_read.count"},
  "budgets":{"max_calls":3,"max_chars":100,"max_peak_chars":100}}"#;

#[test]
fn a_clean_script_has_no_finding() {
    assert_eq!(
        reasons(GOOD, &[r"{}", r#"{"data":{"entry":"0x11e0"}}"#, r"{}"]),
        Vec::<String>::new()
    );
}

#[test]
fn a_hard_coded_address_fails() {
    let bad = GOOD.replace(r#"{"$turn":1,"ptr":"/data/entry"}"#, r#""0x11e0""#);
    let found = reasons(&bad, &[r"{}", r#"{"data":{"entry":"0x11e0"}}"#, r"{}"]);
    assert_eq!(
        found,
        ["/turns/2/call/args/target the value has no provenance entry"]
    );
    let claimed = bad.replace(
        r#""/turns/2/call/args/count""#,
        r#""/turns/2/call/args/target":"schema:func_get.target","/turns/2/call/args/count""#,
    );
    let found = reasons(&claimed, &[r"{}", r#"{"data":{"entry":"0x11e0"}}"#, r"{}"]);
    assert_eq!(found.len(), 1, "{found:?}");
    let cited = bad.replace(
        r#""/turns/2/call/args/count""#,
        r#""/turns/2/call/args/target":"response:1/data/entry","/turns/2/call/args/count""#,
    );
    assert!(reasons(&cited, &[r"{}", r#"{"data":{"entry":"0x11e0"}}"#, r"{}"]).is_empty());
}

#[test]
fn reset_turns_and_late_references_fail() {
    let reset = GOOD.replace(
        r#"{"call":{"tool":"mem_read""#,
        r#"{"reset":true,"call":{"tool":"mem_read""#,
    );
    let found = reasons(&reset, &[r"{}", r#"{"data":{"entry":"0x11e0"}}"#, r"{}"]);
    assert!(
        found.iter().any(|f| f.contains("session_brief")),
        "{found:?}"
    );
    assert!(
        found.iter().any(|f| f.contains("before the context reset")),
        "{found:?}"
    );
    let ahead = GOOD.replace(r#""$turn":1"#, r#""$turn":2"#);
    let found = reasons(&ahead, &[r"{}", r"{}", r"{}"]);
    assert!(found.iter().any(|f| f.contains("not earlier")), "{found:?}");
}

#[test]
fn unused_entries_and_smuggled_answers_fail() {
    let unused = GOOD.replace(
        r#""/turns/0/call/args/path""#,
        r#""/turns/9/call/args/x":"question","/turns/0/call/args/path""#,
    );
    assert_eq!(reasons(&unused, &[r"{}", r"{}", r"{}"]).len(), 1);
    let smuggle = GOOD.replace(
        r#""ptr":"/data/addr"}"#,
        r#""ptr":"/data/items","steps":[{"op":"where","ptr":"/a","eq":"0x11e0"}]}"#,
    );
    let found = reasons(&smuggle, &[r"{}", r"{}", r"{}"]);
    assert!(
        found.iter().any(|f| f.contains("holds the answer")),
        "{found:?}"
    );
}

#[test]
fn schema_sources_reject_addresses() {
    assert!(schema_ok("binary_survey.include", &json(r#""imports""#)));
    assert!(schema_ok(
        "func_list.filter.start_reason",
        &json(r#""symbol""#)
    ));
    assert!(schema_ok("xref_list.args", &json("true")));
    assert!(schema_ok("search.shape", &json(r#""table""#)));
    assert!(!schema_ok("func_get.targets", &json(r#""0x11e0""#)));
    assert!(!schema_ok("nope.x", &json("1")));
    assert!(looks_like_address("fn:0x10"));
    assert!(!looks_like_address("main"));
    assert_eq!(hex_tokens("at 0x1280 and 0x10."), ["0x1280", "0x10"]);
}
