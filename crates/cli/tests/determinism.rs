//! Determinism gates of design Sections 10.11, 13.6 and 15.16: three-process byte equality
//! (AC-186a, AC-186b), no floats (AC-187), the time guard (AC-188) and deep inputs (AC-193).

#![allow(
    clippy::expect_used,
    reason = "test helpers outside test functions use expect"
)]
#![allow(clippy::panic, reason = "a test fails through a panic")]

#[path = "common/mod.rs"]
mod common;
#[path = "hardening/mod.rs"]
mod hardening;

use std::collections::BTreeMap;
use std::io::Cursor;
use std::process::{Command, Stdio};

use ghidorah_cli::{Backend, Options, Shipped, Streams};
use ghidorah_json::{Limits, Value};
use ghidorah_tools::BinaryArg;
use ghidorah_tools::registry::shipped;

use crate::common::{SharedBuf, env, json, root};
use crate::hardening::{
    Fixture, args, by_id, fixtures, float_paths, jsonl, output_of, request, scratch, snapshots,
};

/// The stack size of the deep-input thread (design Section 13.6).
const SMALL_STACK: usize = 256 * 1024;

/// The nesting depth of the deep inputs (AC-193).
const DEEP: usize = 100_000;

/// Gives the load and survey lines of `list`.
fn load_and_survey(list: &[Fixture]) -> Vec<String> {
    let mut lines = Vec::new();
    for f in list {
        lines.push(request(
            &format!("load {}", f.name),
            "binary_load",
            args(&format!(r#"{{"path":"{}"}}"#, f.path)),
        ));
        lines.push(request(
            &format!("survey {}", f.name),
            "binary_survey",
            args(&format!(r#"{{"binary_id":"{}"}}"#, f.id)),
        ));
    }
    lines
}

/// Runs the load, analysis, survey and snapshot of `list` in three processes at once. Makes sure
/// that the stdout bytes and the snapshot bytes are equal.
fn three_processes(name: &str, list: &[Fixture]) {
    assert!(!list.is_empty(), "the tier has fixtures");
    let lines = load_and_survey(list);
    let runs: Vec<(String, BTreeMap<String, Vec<u8>>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..3)
            .map(|k| {
                let lines = &lines;
                scope.spawn(move || {
                    let projects = scratch(&format!("{name}_{k}"));
                    let out = jsonl(&projects, lines);
                    let snaps = snapshots(&projects);
                    let _ = std::fs::remove_dir_all(&projects);
                    (out, snaps)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a run thread"))
            .collect()
    });
    let (first, snaps) = &runs[0];
    let results = by_id(first);
    for f in list {
        let load = &results[&format!("load {}", f.name)];
        assert_eq!(
            load.pointer("/data/analysis/state").and_then(Value::as_str),
            Some("complete"),
            "{}: {load}",
            f.name
        );
        assert!(snaps.contains_key(&f.id), "{} has a snapshot", f.name);
    }
    for (k, (out, other)) in runs.iter().enumerate().skip(1) {
        assert!(out == first, "process {k} gives other stdout bytes");
        assert!(other == snaps, "process {k} gives other snapshot bytes");
    }
}

#[test]
fn ac_186a_three_process_t1() {
    three_processes("t1", &fixtures("T1"));
}

#[test]
#[ignore = "tier2"]
fn ac_186b_three_process_t2() {
    three_processes("t2", &fixtures("T2"));
}

#[test]
fn ac_187_no_floats() {
    let hello = fixtures("T1")
        .into_iter()
        .find(|f| f.name == "hello.gcc-O2")
        .expect("the hello fixture");
    let mut lines = vec![
        request("demo", "binary_load", args(r#"{"builtin":"demo"}"#)),
        request(
            "hello",
            "binary_load",
            args(&format!(r#"{{"path":"{}"}}"#, hello.path)),
        ),
        request(
            "survey",
            "binary_survey",
            args(&format!(
                r#"{{"binary_id":"{}","max_chars":60000}}"#,
                hello.id
            )),
        ),
        request(
            "main",
            "func_get",
            args(&format!(
                r#"{{"binary_id":"{}","target":"main","include":["summary","disasm","ir","decomp","xrefs","callers","callees","strings","vars","notes","why","cfg","jumptables"],"max_chars":60000}}"#,
                hello.id
            )),
        ),
    ];
    // Every example of every shipped tool runs on the demo binary.
    for tool in shipped().tools() {
        for (k, example) in tool.examples.iter().enumerate() {
            let mut a = args(example.args);
            if let Value::Object(members) = &mut a
                && !members.contains_key("binary_id")
                && tool.binary != BinaryArg::None
                && tool.name != "binary_load"
            {
                members.insert("binary_id", Value::from("467a43b75d95c826"));
            }
            lines.push(request(&format!("{}#{k}", tool.name), tool.name, a));
        }
    }
    let projects = scratch("no_floats");
    let out = jsonl(&projects, &lines);
    let _ = std::fs::remove_dir_all(&projects);
    let results = by_id(&out);
    assert_eq!(results.len(), lines.len(), "one result per request");
    let mut floats = Vec::new();
    for (id, value) in &results {
        float_paths(value, id, &mut floats);
    }
    assert!(
        floats.is_empty(),
        "numbers with a fraction or an exponent: {floats:#?}"
    );
}

/// Runs a batch with a 1 ms guard in a process with the system clock. `eval` sets
/// `GHIDORAH_EVAL`. Gives the `data` of the batch result and its warning codes.
fn timed_batch(eval: bool) -> (Value, Vec<String>) {
    let projects = scratch(if eval { "time_eval" } else { "time_guard" });
    let lines = [
        request(
            "load",
            "binary_load",
            args(r#"{"path":"fixtures/bin/crackme.gcc-O0"}"#),
        ),
        request(
            "batch",
            "batch_run",
            args(
                r#"{"steps":[
                    {"id":"list","tool":"func_list","args":{"limit":50}},
                    {"id":"read","tool":"func_get","args":{"targets":{"$ref":"list","ptr":"/data/items/*/id"},"include":["disasm","ir","decomp","cfg"]}},
                    {"id":"again","tool":"func_get","args":{"targets":{"$ref":"list","ptr":"/data/items/*/id"},"include":["decomp"]}},
                    {"id":"last","tool":"calc","args":{"expr":"0x1"}}
                ],"max_ms":1}"#,
            ),
        ),
    ];
    let projects_text = projects.to_string_lossy().into_owned();
    let workspace = root().to_string_lossy().into_owned();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ghidorah"));
    command
        .args([
            "jsonl",
            "--project-root",
            projects_text.as_str(),
            "--root",
            workspace.as_str(),
        ])
        .env_remove("GHIDORAH_FIXED_TIME")
        .env("GHIDORAH_EVAL", if eval { "1" } else { "0" })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = output_of(command, &format!("{}\n", lines.join("\n")));
    let _ = std::fs::remove_dir_all(&projects);
    let results = by_id(&out);
    let batch = results.get("batch").expect("the batch result").clone();
    let warnings = batch
        .get("warnings")
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(|w| w.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let data = batch
        .get("data")
        .cloned()
        .unwrap_or_else(|| panic!("the batch has data: {batch}"));
    (data, warnings)
}

#[test]
fn ac_188_time_guard() {
    let (data, warnings) = timed_batch(false);
    assert_eq!(
        data.get("stopped_by").and_then(Value::as_str),
        Some("time"),
        "{data}"
    );
    assert_eq!(
        data.get("deterministic"),
        Some(&Value::Bool(false)),
        "{data}"
    );
    assert!(warnings.iter().any(|w| w == "W_TIME_STOP"), "{warnings:?}");
    let (data, warnings) = timed_batch(true);
    assert!(
        data.get("stopped_by").is_none(),
        "eval mode has no time stop: {data}"
    );
    assert!(!warnings.iter().any(|w| w == "W_TIME_STOP"), "{warnings:?}");
}

/// Gives the deep-input request lines of AC-193.
fn deep_lines() -> Vec<String> {
    let arrays = format!("{}{}", "[".repeat(DEEP), "]".repeat(DEEP));
    let objects = format!("{}1{}", r#"{"a":"#.repeat(DEEP), "}".repeat(DEEP));
    let nested_calc = |depth: usize| format!("{}0x1{}", "(0x1+".repeat(depth), ")".repeat(depth));
    let c = |text: &str| request("c", "type_get", Value::object([("c", Value::from(text))]));
    let mut lines = vec![
        arrays.clone(),
        objects,
        format!(r#"{{"id":"deep_args","tool":"calc","args":{{"expr":{arrays}}}}}"#),
        request(
            "demo",
            "binary_load",
            args(r#"{"builtin":"demo","analysis":"none"}"#),
        ),
        request(
            "calc_long",
            "calc",
            Value::object([("expr", Value::from(nested_calc(DEEP)))]),
        ),
        request(
            "calc_deep",
            "calc",
            Value::object([("expr", Value::from(nested_calc(150)))]),
        ),
    ];
    for bomb in [
        format!("int {}", "*".repeat(DEEP)),
        format!("int {}", "*".repeat(3_990)),
        format!("int x{}", "[1]".repeat(1_300)),
        format!("{}int{}", "(".repeat(1_990), ")".repeat(1_990)),
        format!("int {}x{}", "(*".repeat(1_300), ")".repeat(1_300)),
        format!("{}int x;{}", "struct { ".repeat(400), "}".repeat(400)),
    ] {
        lines.push(c(&bomb));
    }
    lines
}

#[test]
fn ac_193_deep_inputs() {
    let lines = deep_lines();
    let input = format!("{}\n", lines.join("\n"));
    let (out, done) = std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .name("deep".to_owned())
            .stack_size(SMALL_STACK)
            .spawn_scoped(scope, || {
                // The direct parsers first: JSON, then the calc engine with 100,000 levels.
                let arrays = format!("{}{}", "[".repeat(DEEP), "]".repeat(DEEP));
                let parsed = ghidorah_json::parse(&arrays, &Limits::DEFAULT);
                let expr = format!("{}0x1{}", "(0x1+".repeat(DEEP), ")".repeat(DEEP));
                let mut term = |_: &str| Ok(0u64);
                let evaluated = ghidorah_tools::calc::eval(&expr, &mut term);
                // Then the `jsonl` line path with the shipped tools.
                let mut options = Options::new(&env("deep_inputs"), "cli");
                options.project_root = None;
                options.roots = vec![root()];
                let mut backend = <Shipped as Backend>::open(&options).expect("the backend opens");
                let out = SharedBuf::default();
                let mut streams = Streams {
                    stdin: Box::new(Cursor::new(input.clone().into_bytes())),
                    stdout: Box::new(out.clone()),
                    stderr: Box::new(SharedBuf::default()),
                };
                let _ = ghidorah_cli::call::jsonl_on(&mut backend, None, &mut streams);
                (out.text(), (parsed.is_err(), evaluated.is_err()))
            })
            .expect("the small thread starts");
        handle
            .join()
            .expect("the deep inputs finish in a 256 KiB stack")
    });
    assert_eq!(
        done,
        (true, true),
        "the deep JSON and the deep calc give errors"
    );
    let results: Vec<Value> = out.lines().map(json).collect();
    assert_eq!(results.len(), lines.len(), "one result per line");
    for r in &results {
        let code = r.pointer("/error/code").and_then(Value::as_str);
        assert_ne!(code, Some("INTERNAL_ERROR"), "{r}");
    }
    let calls: BTreeMap<String, &Value> = results
        .iter()
        .filter_map(|r| {
            r.get("id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), r))
        })
        .collect();
    assert_eq!(calls["demo"].get("ok"), Some(&Value::Bool(true)));
    for id in ["calc_long", "calc_deep"] {
        assert_eq!(calls[id].get("ok"), Some(&Value::Bool(false)), "{id}");
    }
}
