//! The run of a batch: step equivalence, one transaction, dry runs, `on_error` and the result
//! shape (AC-175, AC-177, AC-178, AC-182, AC-184).

use ghidorah_json::{Value, write_pretty};
use ghidorah_testkit::golden::{self, Header};
use ghidorah_testkit::rng::{Xoshiro256ss, below};
use ghidorah_tools::Fit;
use ghidorah_tools::batch::STEP_GLOBALS;
use ghidorah_tools::handlers::{self, batch_run};

use crate::support::{
    batch, call, chars, code, data, demo, demo_without_engine, full_registry, int_at, json, lines,
    next0, program, rev, root, state_hash, step_code, steps, text_at,
};

/// The tools whose examples the equivalence test mixes: the read tools, then the tools that
/// edit the program. A batch takes only the actions of `func_edit` that are not destructive.
const MIXED: [&str; 19] = [
    "binary_survey",
    "func_list",
    "func_get",
    "xref_list",
    "search",
    "mem_read",
    "addr_info",
    "calc",
    "fact_check",
    "type_get",
    "history_list",
    "tool_search",
    "session_brief",
    "func_similar",
    "symbol_rename",
    "comment_set",
    "note_write",
    "type_edit",
    "func_edit",
];

/// Gives the examples of [`MIXED`] that a batch step can take: `(tool, args)`. An example
/// with a step global, a destructive action or a setup call does not go in the pool.
fn pool() -> Vec<(&'static str, Value)> {
    let registry = full_registry();
    let mut out = Vec::new();
    for tool in registry.tools().iter().filter(|t| MIXED.contains(&t.name)) {
        for example in tool.examples {
            let args = json(example.args);
            let global = args
                .as_object()
                .is_some_and(|o| o.iter().any(|(k, _)| STEP_GLOBALS.contains(&k)));
            let destructive = tool
                .selector()
                .and_then(|sel| args.get(sel.name).and_then(Value::as_str))
                .and_then(|action| tool.action(action))
                .is_some_and(|a| a.destructive);
            let setup = handlers::func_edit::setup_of(example.args).is_some();
            if !(global || destructive || setup) {
                out.push((tool.name, args));
            }
        }
    }
    out
}

/// The members of a step entry that equal the members of the direct envelope.
const SAME: [&str; 6] = ["ok", "data", "page", "warnings", "next", "error"];

/// The members of the data of an edit that name its commit. The batch has one commit for all
/// of its edits. The direct calls have one commit each.
const COMMIT_MEMBERS: [&str; 2] = ["rev", "tx"];

/// The tools whose results read the journal of committed transactions.
const JOURNAL_READS: [&str; 2] = ["history_list", "session_brief"];

/// The largest number of rounds of the equivalence test.
const MAX_ROUNDS: usize = 60;

/// Gives the examples of one round: the first example that did not run yet, then up to 4
/// other examples at random. No example comes twice in a round.
fn draw(rng: &mut Xoshiro256ss, ran: &[bool]) -> Vec<usize> {
    let mut picked: Vec<usize> = ran.iter().position(|r| !r).into_iter().collect();
    let count = 1 + usize::try_from(below(rng, 5)).unwrap_or(0);
    for _ in 0..count.saturating_mul(4) {
        if picked.len() >= count {
            break;
        }
        let i = usize::try_from(below(rng, ran.len() as u64)).unwrap_or(0);
        if !picked.contains(&i) {
            picked.push(i);
        }
    }
    picked
}

/// Gives the members of [`SAME`] of a step entry or of a direct envelope, in the form that a
/// batch with edits gives. The [`COMMIT_MEMBERS`] of an edit leave the data: the batch commits
/// all edits in one transaction. A batch with edits runs the analysis once after the commit, so
/// its steps have no `analysis_run` call in `next`.
fn same_members(value: &Value, edits: bool) -> Vec<(&'static str, Option<Value>)> {
    SAME.iter()
        .map(|key| {
            let mut member = value.get(key).cloned();
            if let (&"data", Some(Value::Object(data))) = (key, member.as_mut()) {
                for commit in COMMIT_MEMBERS {
                    let _ = data.remove(commit);
                }
            }
            if let (&"next", true, Some(Value::Array(calls))) = (key, edits, member.as_mut()) {
                calls.retain(|c| text_at(c, "/tool") != "analysis_run");
            }
            if member
                .as_ref()
                .is_some_and(|m| m == &Value::Array(Vec::new()))
            {
                member = None;
            }
            (*key, member)
        })
        .collect()
}

#[test]
fn ac_175_step_equivalence() {
    let pool = pool();
    assert!(pool.len() >= 40, "{} examples", pool.len());
    let registry = full_registry();
    let mutating = |tool: &str| registry.get(tool).is_some_and(|(_, t)| t.mutating);
    let edits = pool.iter().filter(|(tool, _)| mutating(tool)).count();
    assert!(edits >= 15, "{edits} edit examples");
    let mut rng = Xoshiro256ss::seed_from_u64(175);
    let mut ran = vec![false; pool.len()];
    let mut round = 0;
    let mut edit_rounds = 0;
    while ran.contains(&false) {
        assert!(round < MAX_ROUNDS, "{round} rounds: {ran:?}");
        round += 1;
        let indices = draw(&mut rng, &ran);
        for i in &indices {
            ran[*i] = true;
        }
        // The journal holds committed transactions only, and a batch commits after its last
        // step. So a journal read runs before the edits of its round: then both runs read
        // the journal at the same rev.
        let mut picked: Vec<&(&str, Value)> = indices.iter().map(|i| &pool[*i]).collect();
        picked.sort_by_key(|(tool, _)| !JOURNAL_READS.contains(tool));
        let count = picked.len();
        let with_edits = picked.iter().any(|(tool, _)| mutating(tool));
        edit_rounds += usize::from(with_edits);
        // The direct session runs the same calls one at a time from the same start state.
        // Neither session has an analysis engine, so an edit marks the analysis stale, as
        // inside the transaction of a batch.
        let mut direct = demo_without_engine();
        let start = rev(&direct);
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
        let mut batched = demo_without_engine();
        let envelope = crate::support::call_value(&mut batched, "batch_run", args);
        let entries = steps(&envelope);
        assert_eq!(entries.len(), count, "round {round}: {envelope}");
        for (i, (entry, want)) in entries.iter().zip(&expected).enumerate() {
            let (got, want_members) = (
                same_members(entry, with_edits),
                same_members(want, with_edits),
            );
            for ((key, a), (_, b)) in got.iter().zip(&want_members) {
                assert_eq!(
                    a, b,
                    "round {round} step {i} {key}: {} {}",
                    picked[i].0, picked[i].1
                );
            }
            assert_eq!(
                int_at(entry, "/chars"),
                chars(want),
                "round {round} step {i}: {} {}",
                picked[i].0,
                picked[i].1
            );
        }
        // A batch with edits commits one transaction with all of them.
        let one = u64::from(rev(&direct) > start);
        assert_eq!(u64::from(with_edits), one, "round {round}");
        assert_eq!(rev(&batched), start + one, "round {round}: {envelope}");
    }
    assert!(edit_rounds >= 5, "{edit_rounds} rounds with edits");
}

const EDITS: &str = r#"{"steps":[
    {"id":"rename","tool":"symbol_rename","args":{"target":"0x1090","name":"read_input"}},
    {"id":"note","tool":"comment_set","args":{"target":"0x1080","kind":"plate","text":"The entry."}},
    {"id":"todo","tool":"note_write","args":{"kind":"todo","text":"Check the loop.","at":"0x11e0"}},
    {"id":"check","tool":"addr_info","args":{"target":"0x1090"}}
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
        text_at(got, "/steps/3/data/symbol/name"),
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
        let named = call(&mut s, "addr_info", r#"{"target":"0x1090"}"#);
        assert_ne!(
            text_at(&named, "/data/symbol/name"),
            "read_input",
            "{named}"
        );
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
        {"id":"check","tool":"addr_info","args":{"target":"0x1090"}}
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
        text_at(got, "/steps/2/data/symbol/name"),
        "read_input",
        "the dry run reads its own edits"
    );
    assert_eq!(rev(&s), rev0);
    assert_eq!(state_hash(&s), hash0);
    assert_eq!(lines(&s), lines0);
    assert_eq!(int_at(&envelope, "/rev"), rev0);
    let after = call(&mut s, "addr_info", r#"{"target":"0x1090"}"#);
    assert_ne!(
        text_at(&after, "/data/symbol/name"),
        "read_input",
        "{after}"
    );
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
