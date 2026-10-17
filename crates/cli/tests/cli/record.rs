//! The call recorder and its replay (AC-201).

use ghidorah_cli::mcp::{ServeOptions, serve};
use ghidorah_cli::record::{self, Entry};
use ghidorah_cli::{Exit, Options};
use ghidorah_json::Value;
use ghidorah_tools::ContentMode;

use crate::common::registry::TestHost;
use crate::common::{env, json, run_in, streams, tmp};

const SESSION: &[&str] = &[
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"item_list","arguments":{"count":3}}}"#,
    r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo_text","arguments":{"text":9}}}"#,
    "not json",
    r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
];

#[test]
fn ac_201_record_replay() {
    let dir = tmp("record");
    let file = dir.join("calls.jsonl");
    let input: String = SESSION.iter().map(|l| format!("{l}\n")).collect();
    let (streams, out, _err) = streams(input.as_bytes());
    let options = Options::new(&env("record_run"), "mcp-1");
    let serve_options = ServeOptions {
        content: ContentMode::Both,
        record: Some(file.clone()),
    };
    assert_eq!(serve::<TestHost>(options.clone(), &serve_options, streams), Exit::Ok);
    let text = std::fs::read_to_string(&file).expect("the record exists");
    let entries = record::parse(&text).expect("the record parses");
    assert_eq!(entries.len(), 5, "one line per answered request: {text}");
    let seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, [1, 2, 3, 4, 5]);
    let replies: Vec<Value> = out.text().lines().map(json).collect();
    let answered: Vec<&Value> = replies
        .iter()
        .filter(|r| r.get("id") != Some(&Value::Null))
        .collect();
    for (entry, reply) in entries.iter().zip(&answered) {
        assert_eq!(&entry.response, *reply, "the record holds the reply");
        assert_eq!(entry.ms, 0, "a fixed time gives 0 ms");
        let chars = u64::try_from(ghidorah_json::write(&entry.response).chars().count())
            .expect("a count");
        assert_eq!(entry.chars, chars);
    }
    assert_eq!(entries[2].copies, 2, "a tool result in mode both has 2 copies");
    assert_eq!(entries[0].copies, 0, "a handshake has no envelope");
    for entry in &entries {
        assert_eq!(Entry::from_json(&entry.to_json()).as_ref(), Ok(entry));
    }

    let diffs = record::replay::<TestHost>(&entries, &options, ContentMode::Both)
        .expect("the replay runs");
    assert!(diffs.is_empty(), "the replay gives equal replies: {diffs:?}");

    let mut changed = entries.clone();
    changed[2].response = json(r#"{"jsonrpc":"2.0","id":3,"result":{}}"#);
    changed[3].ms = 999;
    let diffs = record::replay::<TestHost>(&changed, &options, ContentMode::Both)
        .expect("the replay runs");
    let seqs: Vec<u64> = diffs.iter().map(|d| d.seq).collect();
    assert_eq!(seqs, [3], "ms does not count");
}

#[test]
fn record_appends_and_rejects_bad_lines() {
    let dir = tmp("record_cli");
    let file = dir.join("calls.jsonl");
    let path = file.to_string_lossy().into_owned();
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#;
    for _ in 0..2 {
        let output = run_in::<TestHost>(
            &["mcp", "--record", &path, "--content", "structured"],
            &format!("{line}\n"),
            &env("record_cli_run"),
        );
        assert_eq!(output.code, 0, "{}", output.stderr);
    }
    let text = std::fs::read_to_string(&file).expect("the record exists");
    assert_eq!(text.lines().count(), 2, "a second run appends");
    let error = record::parse("{\"seq\":1}\n").expect_err("an entry needs all fields");
    assert_eq!(error.line, 1);
    let error = record::parse("\n\nnot json\n").expect_err("a line must be JSON");
    assert_eq!(error.line, 3);
    let missing = dir.join("no/such/dir/calls.jsonl");
    let output = run_in::<TestHost>(
        &["mcp", "--record", &missing.to_string_lossy()],
        "",
        &env("record_cli_bad"),
    );
    assert_eq!(output.code, 2, "a record file that does not open is a usage error");
    assert!(output.stdout.is_empty());
}
