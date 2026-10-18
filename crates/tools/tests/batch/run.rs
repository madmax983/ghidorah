//! The run of a batch: step equivalence, one transaction, dry runs, `on_error` and the result
//! shape (AC-175, AC-177, AC-178, AC-182, AC-184).

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::rng::{Xoshiro256ss, below};
use ghidorah_tools::Fit;
use ghidorah_tools::batch::STEP_GLOBALS;
use ghidorah_tools::handlers::batch_run;

use crate::support::{
    batch, call, chars, code, data, demo, full_registry, int_at, json, lines, next0, program, rev,
    root, state_hash, step_code, steps, text_at,
};

/// The read-only tools whose examples the equivalence test mixes.
const MIXED: [&str; 11] = [
    "binary_survey",
    "func_list",
    "func_get",
    "xref_list",
    "search",
    "mem_read",
    "addr_info",
    "calc",
    "type_get",
    "history_list",
    "tool_search",
];

/// Gives the examples of [`MIXED`] that a batch step can take: `(tool, args)`.
fn pool() -> Vec<(&'static str, Value)> {
    let registry = full_registry();
    let mut out = Vec::new();
    for tool in registry.tools().iter().filter(|t| MIXED.contains(&t.name)) {
        for example in tool.examples {
            let args = json(example.args);
            let global = args
                .as_object()
                .is_some_and(|o| o.iter().any(|(k, _)| STEP_GLOBALS.contains(&k)));
            if !global {
                out.push((tool.name, args));
            }
        }
    }
    out
}

/// The members of a step entry that equal the members of the direct envelope.
const SAME: [&str; 6] = ["ok", "data", "page", "warnings", "next", "error"];

#[test]
fn ac_175_step_equivalence() {
    let pool = pool();
    assert!(pool.len() >= 20, "{} examples", pool.len());
    let mut rng = Xoshiro256ss::seed_from_u64(175);
    for round in 0..8 {
        let count = 1 + usize::try_from(below(&mut rng, 5)).unwrap_or(0);
        let picked: Vec<&(&str, Value)> = (0..count)
            .map(|_| {
                let i = usize::try_from(below(&mut rng, pool.len() as u64)).unwrap_or(0);
                &pool[i]
            })
            .collect();
        let mut direct = demo();
        let expected: Vec<Value> = picked
            .iter()
            .map(|(tool, args)| crate::support::call_value(&mut direct, tool, args.clone()))
            .collect();
        let step_list: Vec<Value> = picked
            .iter()
            .enumerate()
            .map(|(i, (tool, args))| {
                Value::object([
                    ("id", Value::from(format!("s{i}"))),
                    ("tool", Value::from(*tool)),
                    ("args", args.clone()),
                ])
            })
            .collect();
        let ids: Vec<Value> = (0..count).map(|i| Value::from(format!("s{i}"))).collect();
        let args = Value::object([
            ("steps", Value::Array(step_list)),
            ("return", Value::Array(ids)),
            ("max_chars", Value::from(60_000)),
        ]);
        let mut batched = demo();
        let envelope = crate::support::call_value(&mut batched, "batch_run", args);
        let entries = steps(&envelope);
        assert_eq!(entries.len(), count, "round {round}: {envelope}");
        for (i, (entry, want)) in entries.iter().zip(&expected).enumerate() {
            for key in SAME {
                assert_eq!(
                    entry.get(key),
                    want.get(key),
                    "round {round} step {i} {key}: {} {}",
                    picked[i].0,
                    picked[i].1
                );
            }
            assert_eq!(
                int_at(entry, "/chars"),
                chars(want),
                "round {round} step {i}"
            );
        }
        assert_eq!(rev(&batched), rev(&direct));
    }
}

const EDITS: &str = r#"{"steps":[
    {"id":"rename","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}},
    {"id":"note","tool":"comment_set","args":{"target":"0x1080","kind":"plate","text":"The entry."}},
    {"id":"todo","tool":"note_write","args":{"kind":"todo","text":"Check the loop.","at":"0x11e0"}},
    {"id":"check","tool":"func_list","args":{"filter":{"name":"read_*"}}}
],"return":["check"]}"#;

#[test]
fn ac_177_atomic() {
    let mut s = demo();
    let (rev0, lines0) = (rev(&s), lines(&s));
    let envelope = batch(&mut s, EDITS);
    let got = data(&envelope);
    assert_eq!(rev(&s), rev0 + 1, "one rev: {envelope}");
    assert_eq!(lines(&s), lines0 + 1, "one journal line");
    assert_eq!(int_at(&envelope, "/rev"), rev0 + 1);
    assert!(text_at(&envelope, "/tx").starts_with("tx:"), "{envelope}");
    assert_eq!(envelope.get("noop"), Some(&Value::Bool(false)));
    assert_eq!(
        text_at(got, "/steps/3/data/items/0/name"),
        "read_input",
        "a read after an edit sees it"
    );
    let tx = text_at(&envelope, "/tx");
    let rows = call(
        &mut s,
        "history_list",
        r#"{"coalesce":false,"since_rev":0}"#,
    );
    let in_tx = rows
        .pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter(|r| text_at(r, "/tx") == tx)
        .count();
    assert_eq!(in_tx, 3, "the three edits share one transaction: {rows}");
    let label = rows
        .pointer("/data/items")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .find(|r| text_at(r, "/tx") == tx)
        .map(|r| text_at(r, "/label"))
        .unwrap_or_default();
    assert_eq!(label, "symbol_rename+comment_set+note_write");

    // A failure at step k rolls back the edits of the steps before it.
    let failing = [
        r#"{"steps":[
            {"id":"a","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}},
            {"id":"b","tool":"comment_set","args":{"target":"0xdeadbeef00","kind":"eol","text":"x"}}
        ]}"#,
        r#"{"steps":[
            {"id":"a","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}},
            {"id":"b","tool":"func_list","args":{},"expect":[{"ptr":"/data/items","op":"len_eq","value":0}]}
        ]}"#,
    ];
    for text in failing {
        let mut s = demo();
        let (rev0, hash0, lines0) = (rev(&s), state_hash(&s), lines(&s));
        let envelope = batch(&mut s, text);
        assert_eq!(envelope.get("ok"), Some(&Value::Bool(false)), "{envelope}");
        assert!(
            text_at(&envelope, "/error/field_path").starts_with("/steps/1"),
            "{envelope}"
        );
        assert_eq!(rev(&s), rev0);
        assert_eq!(state_hash(&s), hash0);
        assert_eq!(lines(&s), lines0);
        let names = call(&mut s, "func_list", r#"{"filter":{"name":"read_*"}}"#);
        assert_eq!(int_at(&names, "/page/total"), 0, "{names}");
    }
    let mut s = demo();
    let envelope = batch(&mut s, failing[0]);
    assert_eq!(code(&envelope), "ADDRESS_UNMAPPED", "{envelope}");
    assert_eq!(text_at(&envelope, "/error/details/step"), "b");
}

#[test]
fn ac_178_dry_run() {
    let mut s = demo();
    let (rev0, hash0, lines0) = (rev(&s), state_hash(&s), lines(&s));
    let text = r#"{"steps":[
        {"id":"rename","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}},
        {"id":"note","tool":"comment_set","args":{"target":"0x1080","kind":"eol","text":"Start."}},
        {"id":"check","tool":"func_list","args":{"filter":{"name":"read_*"}}}
    ],"dry_run":true}"#;
    let envelope = batch(&mut s, text);
    let got = data(&envelope);
    assert_eq!(envelope.get("noop"), Some(&Value::Bool(true)), "{envelope}");
    assert!(envelope.get("tx").is_none(), "{envelope}");
    let diff = envelope
        .get("diff")
        .and_then(Value::as_array)
        .expect("a planned edit list");
    let ops: Vec<String> = diff.iter().map(|d| text_at(d, "/op")).collect();
    assert_eq!(ops, ["SetName", "SetComment"], "{envelope}");
    assert_eq!(
        text_at(got, "/steps/2/data/items/0/name"),
        "read_input",
        "the dry run reads its own edits"
    );
    assert_eq!(rev(&s), rev0);
    assert_eq!(state_hash(&s), hash0);
    assert_eq!(lines(&s), lines0);
    assert_eq!(int_at(&envelope, "/rev"), rev0);
    let after = call(&mut s, "func_list", r#"{"filter":{"name":"read_*"}}"#);
    assert_eq!(int_at(&after, "/page/total"), 0, "{after}");
}

#[test]
fn ac_182_on_error() {
    let steps_text = r#"[
        {"id":"bad","tool":"addr_info","args":{"target":"0xdeadbeef00"}},
        {"id":"dep","tool":"xref_list","args":{"targets":[{"$ref":"bad","ptr":"/data/items/0/addr"}]}},
        {"id":"free","tool":"calc","args":{"expr":"0x10+0x20"}}
    ]"#;
    let mut s = demo();
    let envelope = batch(
        &mut s,
        &format!(r#"{{"steps":{steps_text},"return":["free"]}}"#),
    );
    let entries = steps(&envelope);
    assert_eq!(entries.len(), 3, "{envelope}");
    assert_eq!(step_code(&envelope, 0), "ADDRESS_UNMAPPED", "{envelope}");
    assert_eq!(step_code(&envelope, 1), "SKIPPED_DEPENDENCY", "{envelope}");
    assert_eq!(text_at(&entries[1], "/error/details/failed_step"), "bad");
    assert_eq!(entries[2].get("ok"), Some(&Value::Bool(true)));
    assert_eq!(text_at(&entries[2], "/data/value"), "0x30");
    // The envelope next is the next of the failed step.
    let direct = call(&mut s, "addr_info", r#"{"target":"0xdeadbeef00"}"#);
    assert_eq!(envelope.get("next"), direct.get("next"));

    let envelope = batch(
        &mut s,
        &format!(r#"{{"steps":{steps_text},"on_error":"stop"}}"#),
    );
    let entries = steps(&envelope);
    assert_eq!(entries.len(), 3);
    assert_eq!(step_code(&envelope, 2), "SKIPPED_DEPENDENCY", "{envelope}");
    assert_eq!(int_at(&entries[2], "/fuel"), 0);
    assert!(entries[2].get("data").is_none());
}

#[test]
fn ac_184_result_shape() {
    let mut s = demo();
    let text = r#"{"steps":[
        {"id":"s1","tool":"search","args":{"kind":"string","query":"pass","limit":5}},
        {"id":"s2","tool":"func_list","args":{"sort":"priority","limit":3}},
        {"id":"s3","tool":"calc","args":{"expr":"0x1080+0x10"}}
    ],"return":["s1","s3"]}"#;
    let envelope = batch(&mut s, text);
    let got = data(&envelope);
    batch_run::SPEC
        .output
        .check(got, Fit::Exact)
        .unwrap_or_else(|e| panic!("{e}: {got}"));
    let entries = steps(&envelope);
    let ids: Vec<String> = entries.iter().map(|e| text_at(e, "/id")).collect();
    assert_eq!(ids, ["s1", "s2", "s3"]);
    let tools: Vec<String> = entries.iter().map(|e| text_at(e, "/tool")).collect();
    assert_eq!(tools, ["search", "func_list", "calc"]);
    let with_data: Vec<bool> = entries.iter().map(|e| e.get("data").is_some()).collect();
    assert_eq!(with_data, [true, false, true]);
    for entry in &entries {
        assert!(int_at(entry, "/chars") > 0, "{entry}");
        assert!(int_at(entry, "/fuel") < u64::MAX, "{entry}");
    }
    assert!(
        entries[1].get("page").is_some(),
        "a list step keeps its page"
    );
    assert_eq!(int_at(got, "/budget_used/steps"), 3);
    let fuel: u64 = entries.iter().map(|e| int_at(e, "/fuel")).sum();
    assert_eq!(int_at(got, "/budget_used/fuel"), fuel);
    assert!(int_at(got, "/budget_used/chars") <= chars(&envelope));
    golden::assert_json(
        &root().join("tests/golden/batch/result.json"),
        &Header::new("batch_result", "1"),
        &write_pretty(&envelope),
    );
    // The default return is the last step.
    let envelope = batch(
        &mut s,
        r#"{"steps":[{"id":"a","tool":"calc","args":{"expr":"0x1"}},{"id":"b","tool":"calc","args":{"expr":"0x2"}}]}"#,
    );
    let with_data: Vec<bool> = steps(&envelope)
        .iter()
        .map(|e| e.get("data").is_some())
        .collect();
    assert_eq!(with_data, [false, true]);
}

#[test]
fn batch_examples_on_demo() {
    let header = Header::new("tools_examples", "1")
        .with("fixture", ghidorah_tools::demo::FIXTURE)
        .with(
            "fixture_sha256",
            &ghidorah_base::hex::encode(&ghidorah_base::sha256(ghidorah_tools::demo::BYTES)),
        );
    for example in batch_run::SPEC.examples {
        let mut s = demo();
        let envelope = batch(&mut s, example.args);
        let got = data(&envelope);
        batch_run::SPEC
            .output
            .check(got, Fit::Exact)
            .unwrap_or_else(|e| panic!("{}: {e}", example.args));
        golden::assert_json(
            &root().join(example.golden),
            &header,
            &write_pretty(&envelope),
        );
    }
}

#[test]
fn mutating_batch_reads_stale_analysis_and_reanalyzes_once() {
    let mut s = demo();
    let text = r#"{"steps":[
        {"id":"nr","tool":"func_edit","args":{"action":"set_noreturn","target":"fn:0x11e0","noreturn":true}},
        {"id":"look","tool":"func_list","args":{"limit":1}}
    ],"return":["look"]}"#;
    let envelope = batch(&mut s, text);
    let got = data(&envelope);
    assert_eq!(
        got.pointer("/steps/1/data/items").map(|_| ()),
        Some(()),
        "{envelope}"
    );
    let look = steps(&envelope)[1].clone();
    assert!(look.get("ok") == Some(&Value::Bool(true)), "{look}");
    assert_eq!(
        text_at(&envelope, "/analysis/state"),
        "complete",
        "the re-analysis ran after the commit: {envelope}"
    );
    assert!(program(&s).rev().0 > 1);
}

#[test]
fn failed_step_next_is_the_batch_next() {
    let mut s = demo();
    let envelope = batch(
        &mut s,
        r#"{"steps":[{"id":"a","tool":"func_get","args":{"target":"nosuch_name"}}]}"#,
    );
    let entries = steps(&envelope);
    assert_eq!(
        text_at(&entries[0], "/error/code"),
        "NOT_FOUND",
        "{envelope}"
    );
    let direct = call(&mut s, "func_get", r#"{"target":"nosuch_name"}"#);
    assert_eq!(entries[0].get("error"), direct.get("error"));
    if direct.get("next").is_some() {
        let (tool, _) = next0(&envelope);
        assert_eq!(tool, text_at(&direct, "/next/0/tool"));
    }
}
