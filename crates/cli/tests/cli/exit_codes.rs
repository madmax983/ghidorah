//! Exit codes, stdout data and the broken-pipe rule (AC-150).

use std::io::Write;

use ghidorah_cli::Shipped;

use crate::common::registry::TestHost;
use crate::common::{binary, json, run, run_binary, wait_for};

/// Runs the binary with its stdout pipe closed before the first write.
fn closed_stdout(args: &[&str], stdin: &str) -> std::process::ExitStatus {
    let mut child = binary(args).spawn().expect("the binary starts");
    drop(child.stdout.take());
    let mut input = child.stdin.take().expect("the stdin pipe");
    let _ = input.write_all(stdin.as_bytes());
    let _ = input.flush();
    let status = wait_for(&mut child, 20);
    drop(input);
    status
}

#[test]
fn ac_150_cli_exit_codes() {
    // Code 0: a success writes data only.
    let version = run_binary(&["--version"], "");
    assert_eq!(version.code, 0);
    assert_eq!(
        version.stdout,
        format!("ghidorah {}\n", ghidorah_cli::VERSION)
    );
    let help = run_binary(&["--help"], "");
    assert_eq!(help.code, 0);
    assert!(help.stdout.starts_with("ghidorah: "), "{}", help.stdout);
    let tools = run_binary(&["tools", "--json"], "");
    assert_eq!(tools.code, 0, "{}", tools.stderr);
    assert!(json(&tools.stdout).get("tools").is_some());

    // Code 1: a tool error prints its envelope.
    let unknown = run_binary(&["call", "no_such_tool", "{}"], "");
    assert_eq!(unknown.code, 1, "{}", unknown.stderr);
    let envelope = json(&unknown.stdout);
    assert_eq!(
        envelope.pointer("/error/code").and_then(|v| v.as_str()),
        Some("UNKNOWN_TOOL")
    );

    // Code 2: usage errors write nothing to stdout.
    for args in [
        &["--bogus"][..],
        &["mcp", "--profil", "mini"][..],
        &["call"][..],
        &["call", "x", "{not json"][..],
        &["call", "x", "[1]"][..],
        &["call", "x", "@/no/such/file.json"][..],
        &["frobnicate"][..],
    ] {
        let output = run_binary(args, "");
        assert_eq!(output.code, 2, "{args:?}: {}", output.stderr);
        assert!(output.stdout.is_empty(), "{args:?}: {}", output.stdout);
        assert!(
            output.stderr.starts_with("ghidorah: "),
            "{args:?}: {}",
            output.stderr
        );
    }
    let candidate = run_binary(&["mcp", "--profil", "mini"], "");
    assert!(
        candidate.stderr.contains("Did you mean --profile?"),
        "{}",
        candidate.stderr
    );

    // Code 2: a protocol error of `jsonl`. Stdout holds only envelope lines.
    let calc = r#"{"id":1,"tool":"calc","args":{"expr":"0x1"}}"#;
    let jsonl = run_binary(&["jsonl"], &format!("{{not json\n{calc}\n"));
    assert_eq!(jsonl.code, 2, "{}", jsonl.stderr);
    let lines = jsonl.lines();
    assert_eq!(lines.len(), 2, "one line per request: {}", jsonl.stdout);
    for line in &lines {
        let envelope = json(line);
        assert!(
            envelope
                .get("ok")
                .and_then(ghidorah_json::Value::as_bool)
                .is_some(),
            "an envelope line: {line}"
        );
    }
    assert_eq!(
        json(lines[0])
            .pointer("/error/code")
            .and_then(|v| v.as_str()),
        Some("INVALID_ARGUMENT"),
        "{}",
        lines[0]
    );
    assert_eq!(
        json(lines[1]).pointer("/data/value"),
        Some(&json(r#""0x1""#))
    );

    // A broken pipe on stdout gives code 0.
    assert_eq!(closed_stdout(&["--help"], "").code(), Some(0));
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#;
    let lines = format!("{init}\n").repeat(64);
    assert_eq!(closed_stdout(&["mcp"], &lines).code(), Some(0));
    assert_eq!(closed_stdout(&["tools", "--json"], "").code(), Some(0));
    let args = r#"{"expr":"0x1"}"#;
    assert_eq!(closed_stdout(&["call", "calc", args], "").code(), Some(0));
    let lines = format!("{calc}\n").repeat(64);
    assert_eq!(closed_stdout(&["jsonl"], &lines).code(), Some(0));
}

#[test]
fn exit_codes_of_the_test_registry() {
    let ok = run::<TestHost>(&["call", "echo_text", r#"{"text":"a"}"#], "");
    assert_eq!(ok.code, 0, "{}", ok.stderr);
    assert_eq!(
        json(&ok.stdout).pointer("/data/text"),
        Some(&json(r#""a""#))
    );
    let bad = run::<TestHost>(&["call", "echo_text", r#"{"text":5}"#], "");
    assert_eq!(bad.code, 1);
    assert_eq!(
        json(&bad.stdout).pointer("/error/code"),
        Some(&json(r#""INVALID_ARGUMENT""#))
    );
    let piped = run::<TestHost>(&["call", "echo_text", "-"], r#"{"text":"from stdin"}"#);
    assert_eq!(piped.code, 0, "{}", piped.stderr);
    assert_eq!(
        json(&piped.stdout).pointer("/data/text"),
        Some(&json(r#""from stdin""#))
    );
    let empty = run::<TestHost>(&["call", "echo_text"], "");
    assert_eq!(empty.code, 1, "the text is missing");
    assert_eq!(
        json(&empty.stdout).pointer("/error/code"),
        Some(&json(r#""MISSING_ARGUMENT""#))
    );
    let shipped = run::<Shipped>(&["call", "no_such_tool"], "");
    assert_eq!(shipped.code, 1);
}

#[test]
fn call_reads_arguments_from_a_file() {
    let dir = crate::common::tmp("call_file");
    let path = dir.join("args.json");
    std::fs::write(&path, r#"{"text":"file"}"#).expect("the file writes");
    let arg = format!("@{}", path.display());
    let output = run::<TestHost>(&["call", "echo_text", &arg, "--format", "jsonl"], "");
    assert_eq!(output.code, 0, "{}", output.stderr);
    assert_eq!(output.lines().len(), 1, "jsonl prints one line");
    assert_eq!(
        json(&output.stdout).pointer("/data/text"),
        Some(&json(r#""file""#))
    );
    let pretty = run::<TestHost>(&["call", "echo_text", r#"{"text":"p"}"#], "");
    assert!(pretty.lines().len() > 1, "json prints pretty text");
    let text = run::<TestHost>(
        &["call", "echo_text", r#"{"text":"t"}"#, "--format", "text"],
        "",
    );
    assert!(text.lines().contains(&"/data/text t"), "{}", text.stdout);
    assert!(text.lines().contains(&"/ok true"), "{}", text.stdout);
}
